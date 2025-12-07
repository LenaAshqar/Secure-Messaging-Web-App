/* === Privacy & visibility flags === */
const REDACT_SENSITIVE = true;  // keep true in production (never show nonce/AAD values)
const SHOW_LOGS_PANEL = true;

const $ = id => document.getElementById(id);

const setStatus = (msg, cls = "") => {
    const s = $("status");
    if (!s) return;
    s.textContent = msg;
    s.className = "status " + cls;
};

let CURRENT_USER = null;
let ALL_USERS = [];
let LAST_NONCE = "";
const AAD_VALUE = null;  // reserved for future use

if (!SHOW_LOGS_PANEL) {
    const sec = $("logsSection");
    if (sec) sec.style.display = "none";
}

function now(){
    const d=new Date();
    return d.toLocaleTimeString();
}

function log(msg, type="info"){
    if (!SHOW_LOGS_PANEL) return;
    const line = document.createElement("div");
    line.className = "logline " + (type==="ok"?"log-ok":type==="warn"?"log-warn":type==="err"?"log-err":"");
    line.textContent = `[${now()}] ${msg}`;
    const area = $("logs");
    area.appendChild(line);
    area.scrollTop = area.scrollHeight;
}

async function postJSON(path, data){
    return fetch(path, {
        method:"POST",
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(data)
    });
}

function setBusy(b){
    if ($("btnSend")) $("btnSend").disabled = b;
    if ($("btnVerify")) $("btnVerify").disabled = b;
}

/* ---------- Card switching (login / app / fake phishing) ---------- */

function showCard(cardId){
    const ids = ["loginCard","appCard","phishFullCard"];
    ids.forEach(id=>{
        const el = $(id);
        if (!el) return;
        if (id === cardId) el.classList.remove("hidden");
        else el.classList.add("hidden");
    });
}

/* ---------- Lock warning helpers ---------- */

function showLockWarning() {
    const w = $("lockWarning");
    if (w) w.classList.remove("hidden");
}

function hideLockWarning() {
    const w = $("lockWarning");
    if (w) w.classList.add("hidden");
}

/* ---------- Load users (for recipient list) ---------- */

async function loadUsers(){
    try{
        const r = await fetch("/users");
        const j = await r.json();
        ALL_USERS = j.users || [];
        log("Loaded users from server: " + ALL_USERS.join(", "), "info");
        updateRecipientOptions();
    }catch(e){
        const ls = $("loginStatus");
        if(ls) ls.textContent = "Error loading users: " + e.message;
        log("Error loading users list from /users: " + e.message, "err");
    }
}

function updateRecipientOptions(){
    const recSel = $("recipient");
    if (!recSel) return;
    recSel.innerHTML = "";

    if (!ALL_USERS.length){
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "No users available";
        recSel.appendChild(opt);
        return;
    }

    ALL_USERS.forEach(u => {
        if (u === CURRENT_USER) return; // cannot send to self in this simple demo
        const opt = document.createElement("option");
        opt.value = u;
        opt.textContent = u;
        recSel.appendChild(opt);
    });

    if (!recSel.value && recSel.options.length > 0){
        recSel.selectedIndex = 0;
    }
}

/* ---------- Show password toggle ---------- */

const togglePassword = $("togglePassword");
if (togglePassword){
    togglePassword.addEventListener("change", ()=>{
        const pwd = $("loginPassword");
        if (!pwd) return;
        pwd.type = togglePassword.checked ? "text" : "password";
    });
}

/* ---------- Login handling ---------- */

$("btnLogin").addEventListener("click", async (ev)=>{
    ev.preventDefault();
    const userInput = $("loginUser");
    const chosen = userInput ? userInput.value.trim() : "";
    const pwdInput = $("loginPassword");
    const pwd = pwdInput ? pwdInput.value : "";
    const ls = $("loginStatus");

    if (!chosen){
        if (ls) ls.textContent = "Please enter a username.";
        log("Login attempt with empty username.", "warn");
        return;
    }
    if (!pwd){
        if (ls) ls.textContent = "Please enter a password.";
        log(`Login attempt for user "${chosen}" with empty password.`, "warn");
        return;
    }

    try{
        if (ls) ls.textContent = `Checking credentials for "${chosen}"…`;
        log(`Sending login request for username="${chosen}" to /login.`, "info");

        const r = await postJSON("/login", { username: chosen, password: pwd });
        const j = await r.json();

        // Locked?
        if (j.locked){
            showLockWarning();
            const errMsg = j.error || "This account is locked.";
            if (ls) ls.textContent = errMsg;
            log(`Login failed for "${chosen}" — account is locked. Reason: ${errMsg}`, "err");
            return;
        }

        if (!r.ok || !j.ok){
            hideLockWarning();
            const errMsg = j.error || "Login failed.";
            if(ls) ls.textContent = errMsg;
            log(`Login failed for "${chosen}". Server said: ${errMsg}`, "err");
            return;
        }

        // Success
        hideLockWarning();
        CURRENT_USER = chosen;
        if (ls) ls.textContent = `Logged in as ${CURRENT_USER}.`;
        log(`Login successful for user "${CURRENT_USER}".`, "ok");

        const label = $("currentUserLabel");
        if (label) label.textContent = CURRENT_USER;

        updateRecipientOptions();
        setStatus("Idle.", "");
        showCard("appCard");
    }
    catch(e){
        if (ls) ls.textContent = "Login error: " + e.message;
        log(`Login error for username="${chosen}": ${e.message}`, "err");
    }
});

/* ---------- Logout handling ---------- */

$("btnLogout").addEventListener("click", (ev)=>{
    ev.preventDefault();
    if (!CURRENT_USER){
        log("Logout clicked but no user is currently logged in.", "warn");
    } else {
        log(`User "${CURRENT_USER}" logged out. Clearing state.`, "info");
    }

    CURRENT_USER = null;
    LAST_NONCE = "";
    const label = $("currentUserLabel");
    if (label) label.textContent = "–";

    if ($("compose"))   $("compose").value = "";
    if ($("cipher"))    $("cipher").value = "";
    if ($("decrypted")) $("decrypted").value = "";

    setStatus("Logged out. Please log in again.", "");
    const ls = $("loginStatus");
    if (ls) ls.textContent = "Enter username, password, then click Enter.";

    showCard("loginCard");
});

/* ---------- Encrypt & Send ---------- */

$("btnSend").addEventListener("click", async (ev)=>{
    ev.preventDefault();
    if (!CURRENT_USER){
        setStatus("Please log in first.", "err");
        log("Encrypt attempted without login.", "err");
        return;
    }

    const msg = $("compose").value;
    const recipientSel = $("recipient");
    const receiver = recipientSel ? recipientSel.value : null;

    if (!receiver){
        setStatus("Choose a recipient.", "err");
        log(`Encrypt aborted: no recipient selected. Acting user="${CURRENT_USER}".`, "warn");
        return;
    }

    setBusy(true);
    setStatus("Encrypting…");
    log(`Encrypt request: sender="${CURRENT_USER}", receiver="${receiver}", length=${msg.length} bytes.`, "info");

    try{
        const r = await postJSON("/encrypt", {
            sender: CURRENT_USER,
            receiver: receiver,
            plaintext: msg,
            aad: AAD_VALUE
        });
        const j = await r.json();
        if (!r.ok){
            const errMsg = j.error || "encrypt failed (unknown server error)";
            throw new Error(errMsg);
        }

        LAST_NONCE = j.nonce || "";
        const bundle = JSON.stringify({
            sender:    j.sender || CURRENT_USER,
            receiver:  j.receiver || receiver,
            ciphertext:j.ciphertext || "",
            nonce:     j.nonce || "",
            signature: j.signature || ""
        }, null, 2);
        $("cipher").value = bundle;

        setStatus("Encrypted ✓","ok");
        log(`Encrypt success. Bundle ready for transport from "${CURRENT_USER}" to "${receiver}".`, "ok");
        if (REDACT_SENSITIVE) {
            log("Nonce generated (value redacted from UI).", "info");
            log(AAD_VALUE ? "AAD: present" : "AAD: none", "info");
        } else {
            log(`Nonce (Base64): ${LAST_NONCE}`, "info");
            log(`AAD: ${AAD_VALUE === null ? "(none)" : String(AAD_VALUE)}`, "info");
        }
    }catch(e){
        setStatus("Error: " + e.message, "err");
        log(`Encrypt error for sender="${CURRENT_USER}", receiver="${receiver}": ${e.message}`, "err");
    }finally{
        setBusy(false);
    }
});

/* ---------- Verify & Decrypt ---------- */

$("btnVerify").addEventListener("click", async (ev)=>{
    ev.preventDefault();
    if (!CURRENT_USER){
        setStatus("Please log in first.", "err");
        log("Decrypt attempted without login.", "err");
        return;
    }

    const raw = $("cipher").value.trim();
    let ct = "", nonce = "", sig = "", sender = "", receiverFromBundle = "";

    try{
        if (raw.startsWith("{")){
            const obj = JSON.parse(raw);
            sender  = (obj.sender || "").trim();
            receiverFromBundle = (obj.receiver || "").trim();
            ct      = (obj.ciphertext || "").trim();
            nonce   = (obj.nonce || "").trim();
            sig     = (obj.signature || "").trim();
        } else {
            setStatus("Please provide a JSON bundle.", "err");
            log("Decrypt aborted: transport content is not JSON.", "err");
            return;
        }
    }catch(parseErr){
        setStatus("Invalid bundle JSON.", "err");
        log(`Transport JSON parse failed: ${String(parseErr)}`, "err");
        return;
    }

    if (!sender){
        setStatus("Missing sender in bundle.", "err");
        log("Bundle validation failed: missing 'sender' field.", "warn");
        return;
    }
    if (!ct || !nonce || !sig){
        setStatus("Bundle incomplete (ciphertext/nonce/signature).", "err");
        log(`Bundle validation failed: missing fields. HasCiphertext=${!!ct}, HasNonce=${!!nonce}, HasSignature=${!!sig}.`, "warn");
        return;
    }

    const receiver = CURRENT_USER;

    setBusy(true);
    setStatus("Decrypting…");
    log(`Decrypt request: actingReceiver="${receiver}", bundleSender="${sender}", bundleReceiver="${receiverFromBundle}".`, "info");

    try{
        const r = await postJSON("/decrypt", {
            sender:    sender,
            receiver:  receiver,
            ciphertext:ct,
            nonce:     nonce,
            signature: sig,
            aad:       AAD_VALUE
        });
        const j = await r.json();
        if (!r.ok){
            const errMsg = j.error || "decrypt failed (unknown server error)";
            throw new Error(errMsg);
        }

        $("decrypted").value = j.plaintext || "";
        setStatus("Decrypted ✓","ok");
        log(`Decryption success. Acting receiver="${receiver}", original sender="${sender}".`, "ok");
    }catch(e){
        const msg = String(e.message || e);
        setStatus("Error: " + msg, "err");
        log(`Decrypt error for actingReceiver="${receiver}", bundleSender="${sender}": ${msg}`, "err");

        if (msg.includes("wrong key or you are not the intended recipient")) {
            log("This indicates that your ECDH key does not match the one used for encryption – you are not the intended recipient.", "warn");
        }
    }finally{
        setBusy(false);
    }
});

/* ---------- Clear logs ---------- */

$("btnClear").addEventListener("click", (ev)=>{
    ev.preventDefault();
    if (SHOW_LOGS_PANEL) $("logs").innerHTML = "";
    setStatus("Idle.");
    log("Logs cleared by user.", "info");
});

/* ---------- Dictionary attack (simulate login attempts BEFORE login) ---------- */

$("btnDictAttackLogin").addEventListener("click", async (ev)=>{
    ev.preventDefault();

    const usernameInput = $("loginUser");
    const username = usernameInput ? usernameInput.value.trim() : "";

    if (!username){
        alert("Enter a username to attack.");
        log("Dictionary attack attempted without a target username.", "err");
        return;
    }

    log(`Starting dictionary attack simulation against "${username}".`, "info");

    try{
        const r = await postJSON("/attack/dictionary", { username });
        const j = await r.json();

        if (!r.ok){
            throw new Error(j.error || "Server error running dictionary attack.");
        }

        const locked = j.locked === true;
        const failCount = j.failed_attempts ?? 0;
        const maxFail = j.max_failed_attempts ?? 3;

        if (locked) {
            showLockWarning();
        } else {
            hideLockWarning();
        }

        if (j.success){
            alert(
                `Dictionary Attack Succeeded!\n\n` +
                `Target user: ${j.username}\n` +
                `Guessed password: "${j.guessed_password}"\n` +
                `Attempts used in this simulation: ${j.attempts}\n` +
                `Total failed attempts recorded: ${failCount}/${maxFail}\n\n` +
                (locked
                    ? `The account is now LOCKED by the system for protection.`
                    : `The account has NOT yet reached the lockout threshold.`)
            );

            log(`[DICT] SUCCESS — guessed password "${j.guessed_password}" for "${j.username}".`, "err");
            log(`[DICT] Failed attempts recorded so far: ${failCount}/${maxFail}.`, locked ? "err" : "warn");
            setStatus("Dictionary attack succeeded (weak password).", "err");
        } else {
            alert(
                `Dictionary Attack Failed.\n\n` +
                `Target user: ${j.username}\n` +
                `Attempts used in this simulation: ${j.attempts}\n` +
                `Total failed attempts recorded: ${failCount}/${maxFail}\n\n` +
                (locked
                    ? `The account is now LOCKED after too many failed attempts.`
                    : `The account remains unlocked, but the attack did not succeed with this dictionary.`)
            );

            log(`[DICT] FAILED — could not guess password for "${j.username}".`, locked ? "warn" : "ok");
            log(`[DICT] Failed attempts recorded so far: ${failCount}/${maxFail}.`, locked ? "warn" : "info");
            setStatus("Dictionary attack attempt detected.", locked ? "err" : "warn");
        }

        if (Array.isArray(j.tried_passwords)) {
            log(`[DICT] Tried passwords: ${JSON.stringify(j.tried_passwords)}`, "info");
        }
    }
    catch(e){
        alert("Attack error: " + e.message);
        log(`Dictionary attack error targeting "${username}": ${e.message}`, "err");
    }
});

/* ---------- Base64 signature forge helper ---------- */

function forgeBase64Signature(sig) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!sig || sig.length === 0) return sig;

    const lastChar = sig[sig.length - 1];
    const idx = alphabet.indexOf(lastChar);
    if (idx === -1) return sig.slice(0, -1) + "A";

    const replacement = alphabet[(idx + 1) % alphabet.length];
    return sig.slice(0, -1) + replacement;
}

/* ---------- Forged signature attack (tamper bundle) ---------- */

$("btnForgeSig").addEventListener("click", (ev)=>{
    ev.preventDefault();

    const raw = $("cipher").value.trim();
    if (!raw){
        setStatus("No bundle to tamper with.", "err");
        log("Forge signature aborted: Transport box is empty.", "warn");
        return;
    }

    let obj;
    try{
        obj = JSON.parse(raw);
    }catch(e){
        setStatus("Bundle is not valid JSON.", "err");
        log(`Forge signature aborted: JSON parse error: ${String(e)}`, "err");
        return;
    }

    if (!obj.signature){
        setStatus("Bundle has no signature field.", "err");
        log("Forge signature aborted: no 'signature' field in bundle.", "warn");
        return;
    }

    const originalSig = obj.signature;
    const forgedSig = forgeBase64Signature(originalSig);

    if (forgedSig === originalSig){
        obj.signature = "FORGED_" + originalSig;
    } else {
        obj.signature = forgedSig;
    }

    $("cipher").value = JSON.stringify(obj, null, 2);

    setStatus("Signature forged. Try Verify & Decrypt.", "err");
    log("ATTACK: Signature field in bundle was tampered (forged) before delivery.", "err");
    log("When you now click 'Verify & Decrypt', the backend should detect signature failure.", "info");
});

/* ---------- Phishing attack simulation ---------- */

const btnShowPhish = $("btnShowPhish");
if (btnShowPhish){
    btnShowPhish.addEventListener("click", (ev)=>{
        ev.preventDefault();
        const panel = $("phishPanel");
        if (!panel) return;

        panel.innerHTML =
            '<div style="font-family:var(--mono); white-space:pre-wrap; font-size:13px;">' +
            'From: <b>security@kfupm-it-support.com</b>\n' +
            'To:   &lt;your_email@kfupm.edu.sa&gt;\n' +
            'Subject: <b>URGENT: Account Suspension Notice</b>\n\n' +
            'Dear user,\n\n' +
            'We detected unusual activity on your Secure Messenger account.\n' +
            'To avoid <b>immediate suspension</b>, please confirm your username and password\n' +
            'by logging in at the following link within the next 15 minutes:\n\n' +
            '  http://secure-messenger-security-check.example.com/login\n\n' +
            'Failure to do so may result in <b>permanent loss of access</b>.\n\n' +
            'Best regards,\n' +
            'IT Security Team\n' +
            '</div>';

        log("Phishing email displayed. It uses urgency, fear, and a fake link to trick the user.", "warn");
        setStatus("Phishing email shown in simulation.", "warn");
    });
}

const btnClickPhishLink = $("btnClickPhishLink");
if (btnClickPhishLink){
    btnClickPhishLink.addEventListener("click", (ev)=>{
        ev.preventDefault();
        showCard("phishFullCard");
        log("User clicked the suspicious link in the phishing email (simulation). Fake login page displayed.", "warn");
        setStatus("Fake phishing login page visible.", "warn");
    });
}

const btnPhishBack = $("btnPhishBack");
if (btnPhishBack){
    btnPhishBack.addEventListener("click", (ev)=>{
        ev.preventDefault();
        if (CURRENT_USER){
            showCard("appCard");
        } else {
            showCard("loginCard");
        }
        log("User navigated back from fake phishing login to the main app.", "info");
        setStatus("Returned from phishing simulation.", "ok");
    });
}

const btnSubmitPhish = $("btnSubmitPhish");
if (btnSubmitPhish){
    btnSubmitPhish.addEventListener("click", (ev)=>{
        ev.preventDefault();
        const u = $("phishUser") ? $("phishUser").value.trim() : "";
        const p = $("phishPass") ? $("phishPass").value.trim() : "";

        if (!u && !p){
            alert("In this simulation, enter some dummy username/password to see what happens.");
            return;
        }

        alert(
            "Phishing Simulation:\n\n" +
            "You just entered credentials into a FAKE login page.\n\n" +
            "In a real attack, the attacker would now have your username and password.\n" +
            "Always check the URL, HTTPS lock icon, and sender before entering credentials."
        );

        log(
            `PHISHING SIMULATION: User typed credentials into fake page. ` +
            `Captured values (for demo only): username="${u}", password="${p}".`,
            "err"
        );
        setStatus("User fell for phishing (simulation only).", "err");

        if ($("phishUser")) $("phishUser").value = "";
        if ($("phishPass")) $("phishPass").value = "";
    });
}

/* ---------- Init ---------- */

window.addEventListener("DOMContentLoaded", async ()=>{
    showCard("loginCard");
    await loadUsers();
});
