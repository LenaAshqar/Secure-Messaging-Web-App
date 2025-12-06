// static/script.js
async function postJSON(path, body) {
    const r = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    const j = await r.json();
    return { ok: r.ok, json: j };
}

async function getJSON(path) {
    const r = await fetch(path);
    const j = await r.json();
    return { ok: r.ok, json: j };
}

function log(msg) {
    const el = document.getElementById('log');
    el.textContent = `${new Date().toISOString()} - ${msg}\n` + el.textContent;
}

document.addEventListener('DOMContentLoaded', () => {
    const btnGenKeys = document.getElementById('btnGenKeys');
    const btnMyPubkey = document.getElementById('btnMyPubkey');
    const btnRegisterMyKey = document.getElementById('btnRegisterMyKey');
    const btnGetPubkey = document.getElementById('btnGetPubkey');
    const btnReplacePubkey = document.getElementById('btnReplacePubkey');
    const pubkeyArea = document.getElementById('pubkeyArea');

    const btnEncrypt = document.getElementById('btnEncrypt');
    const btnDecrypt = document.getElementById('btnDecrypt');
    const transport = document.getElementById('transport');
    const plaintext = document.getElementById('plaintext');
    const toUser = document.getElementById('toUser');
    const received = document.getElementById('received');
    const plaintextOut = document.getElementById('plaintextOut');
    const ciphertextDisplay = document.getElementById('ciphertextDisplay');
    const signatureStatus = document.getElementById('signatureStatus');
    const attackOutput = document.getElementById('attackOutput');
    const btnDictionary = document.getElementById('btnDictionary');
    const btnForge = document.getElementById('btnForge');
    const btnPhishing = document.getElementById('btnPhishing');
    const btnDos = document.getElementById('btnDos');

    btnGenKeys.onclick = async () => {
        const r = await postJSON('/generate_keys', {});
        if (r.ok) {
            log('Generated new keypair for session');
        } else {
            log('Failed to generate keys: ' + (r.json.error || JSON.stringify(r.json)));
        }
    };

    btnMyPubkey.onclick = async () => {
        const r = await getJSON('/my_pubkey');
        if (r.ok) {
            pubkeyArea.textContent = 'Signing key:\n' + r.json.signing_pub_pem + '\n\nECDH key:\n' + r.json.ecdh_pub_pem + '\nFingerprint: ' + r.json.fingerprint;
            log('Displayed my public keys.');
        } else {
            pubkeyArea.textContent = JSON.stringify(r.json);
        }
    };

    btnRegisterMyKey.onclick = async () => {
        // fetch my pubkeys first then register under my username
        const my = await getJSON('/my_pubkey');
        if (!my.ok) { log('Could not get my pubkeys'); return; }
        // username is shown on page
        const role = document.getElementById('role').textContent.trim().toLowerCase();
        const r = await postJSON(`/register/${role}`, {
            signing_pub_pem: my.json.signing_pub_pem,
            ecdh_pub_pem: my.json.ecdh_pub_pem
        });
        if (r.ok) {
            log(`Registered my public keys as ${role} (fingerprint ${r.json.fingerprint})`);
        } else {
            log('Register failed: ' + JSON.stringify(r.json));
        }
    };

    btnGetPubkey.onclick = async () => {
        const other = document.getElementById('otherUser').value;
        const r = await getJSON(`/pubkey/${other}`);
        if (r.ok) {
            pubkeyArea.textContent = 'Signing key:\n' + r.json.pub_pem.signing + '\n\nECDH key:\n' + r.json.pub_pem.ecdh + '\nFingerprint: ' + r.json.fingerprint;
            log(`Fetched public keys for ${other}`);
        } else {
            pubkeyArea.textContent = JSON.stringify(r.json);
            log('Fetch failed: ' + JSON.stringify(r.json));
        }
    };

    btnReplacePubkey.onclick = async () => {
        const other = document.getElementById('otherUser').value;
        // Attacker will replace other user's key with attacker's own key (session)
        const my = await getJSON('/my_pubkey');
        if (!my.ok) { log('Could not get my pubkeys'); return; }
        const r = await postJSON(`/replace_pubkey/${other}`, {
            signing_pub_pem: my.json.signing_pub_pem,
            ecdh_pub_pem: my.json.ecdh_pub_pem
        });
        if (r.ok) {
            log(`Replaced ${other}'s public key in directory with my key (MITM simulation). New fingerprint: ${r.json.new_fingerprint}`);
        } else {
            log('Replace failed: ' + JSON.stringify(r.json));
        }
    };

    btnEncrypt.onclick = async () => {
        const to = toUser.value;
        const pt = plaintext.value;
        if (!pt) { log('Enter plaintext first'); return; }
        const r = await postJSON('/encrypt', { plaintext: pt, receiver_username: to });
        if (r.ok) {
            // place the full bundle in transport box (copy/paste between windows)
            transport.value = JSON.stringify(r.json, null, 2);
            ciphertextDisplay.textContent = r.json.ciphertext || '';
            log(`Created transport bundle for ${to}. Message id: ${r.json.message_id || 'n/a'}`);
        } else {
            log('Encrypt error: ' + JSON.stringify(r.json));
        }
    };

    btnDecrypt.onclick = async () => {
        const raw = received.value;
        if (!raw) { log('Paste transport bundle first'); return; }
        let obj;
        try { obj = JSON.parse(raw); } catch (e) { log('Invalid JSON'); return; }
        const r = await postJSON('/decrypt', obj);
        if (r.ok) {
            plaintextOut.textContent = r.json.plaintext + '\n\n(ts: ' + (r.json.timestamp || '') + ', id: ' + (r.json.message_id || '') + ')';
            signatureStatus.textContent = r.json.signature_valid ? 'Signature verified (integrity/authentication OK)' : 'Signature verification failed';
            log('Decryption success');
        } else {
            plaintextOut.textContent = '';
            signatureStatus.textContent = 'Signature verification failed or bundle invalid.';
            log('Decrypt error: ' + JSON.stringify(r.json));
        }
    };

    btnDictionary.onclick = async () => {
        const target = document.getElementById('otherUser').value;
        const r = await getJSON(`/simulate/dictionary?target=${encodeURIComponent(target)}`);
        attackOutput.textContent = JSON.stringify(r.json, null, 2);
        log(r.ok ? `Dictionary attack against ${target} detected: ${r.json.detected}` : 'Dictionary simulation failed');
    };

    btnForge.onclick = async () => {
        const r = await getJSON('/simulate/forgery');
        attackOutput.textContent = JSON.stringify(r.json, null, 2);
        log(r.ok ? 'Forgery attempt verified and blocked.' : 'Forgery simulation failed');
    };

    btnPhishing.onclick = async () => {
        const r = await getJSON('/simulate/phishing');
        attackOutput.textContent = JSON.stringify(r.json, null, 2);
        log(r.ok ? 'Phishing lure flagged for warning.' : 'Phishing simulation failed');
    };

    btnDos.onclick = async () => {
        const r = await getJSON('/simulate/dos');
        attackOutput.textContent = JSON.stringify(r.json, null, 2);
        log(r.ok ? `DoS burst count ${r.json.requests_seen}` : 'DoS simulation throttled');
    };

});
