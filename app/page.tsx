"use client";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowUpRight, Check, Code2, Fingerprint, KeyRound, LockKeyhole, Plus, ShieldCheck, Trash2, Unlock, X } from "lucide-react";
import { derive, seal, unseal, toBase64, type Envelope, type Task, type Unlocked } from "@/lib/veil-crypto";
type VaultState = { initialized: boolean; envelope: Envelope; revision: number };
export default function Home() {
  const [vault, setVault] = useState<VaultState | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [invite, setInvite] = useState("");
  const [newTask, setNewTask] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [about, setAbout] = useState(false);
  const [saved, setSaved] = useState(true);
  const credentials = useRef<Unlocked | null>(null);
  const epoch = useRef(0);
  const lastActivity = useRef(0);
  const pendingKey = useRef<string | null>(null);
  const aboutRef = useRef<HTMLDialogElement>(null);
  const lock = useCallback(() => {
    epoch.current += 1; credentials.current = null;
    setIsUnlocked(false); setTasks([]); setNewTask(""); setPassphrase(""); setConfirmation(""); setError(""); setMessage(""); setBusy(false); setSaved(true);
  }, []);
  const load = useCallback(async () => {
    setError("");
    try {
      const response = await fetch("/api/vault", { cache: "no-store" });
      const data = await response.json() as VaultState & { error?: string };
      if (!response.ok) throw new Error(data.error);
      setVault(data);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load the vault."); }
  }, []);
  useEffect(() => {
    const consumeFragment = () => {
      const fragment = new URLSearchParams(window.location.hash.slice(1));
      pendingKey.current = fragment.get("key"); setInvite(fragment.get("setup") || "");
      if (fragment.has("key") || fragment.has("setup")) window.history.replaceState(null, "", window.location.pathname + window.location.search);
      void load();
    };
    consumeFragment();
    window.addEventListener("hashchange", consumeFragment);
    window.addEventListener("pagehide", lock);
    return () => { window.removeEventListener("hashchange", consumeFragment); window.removeEventListener("pagehide", lock); credentials.current = null; pendingKey.current = null; epoch.current += 1; };
  }, [load, lock]);
  const unlockWith = useCallback(async (secret: string, current: VaultState) => {
    setBusy(true); setError(""); setMessage("");
    const generation = epoch.current;
    try {
      if (!current.initialized) throw new Error("Setup pending");
      const unlocked = await derive(secret, current.envelope.salt);
      const clearTasks = await unseal(current.envelope, unlocked.key);
      if (generation !== epoch.current) return;
      credentials.current = unlocked; setTasks(clearTasks); setIsUnlocked(true); lastActivity.current = Date.now(); setSaved(true);
    } catch {
      if (generation === epoch.current) setError(current.initialized ? "That key couldn't decrypt this list. Check it and try again." : "Owner setup is pending. This preview has no public unlock key.");
    } finally { if (generation === epoch.current) { setBusy(false); setPassphrase(""); } }
  }, []);
  useEffect(() => {
    if (vault && pendingKey.current) { const key = pendingKey.current; pendingKey.current = null; void unlockWith(key, vault); }
  }, [vault, unlockWith]);
  useEffect(() => {
    if (!isUnlocked) return;
    const touch = () => { lastActivity.current = Date.now(); };
    window.addEventListener("pointerdown", touch); window.addEventListener("keydown", touch);
    const timer = window.setInterval(() => { if (Date.now() - lastActivity.current > 300_000) lock(); }, 5_000);
    return () => { clearInterval(timer); window.removeEventListener("pointerdown", touch); window.removeEventListener("keydown", touch); };
  }, [isUnlocked, lock]);
  useEffect(() => { if (about) aboutRef.current?.showModal(); else aboutRef.current?.close(); }, [about]);
  async function setup(event: FormEvent) {
    event.preventDefault(); if (!vault) return;
    if (passphrase.length < 16) { setError("Choose a unique key of at least 16 characters, ideally 5–6 random words."); return; }
    if (passphrase !== confirmation) { setError("The two keys don't match."); return; }
    setBusy(true); setError(""); const generation = epoch.current;
    try {
      const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
      const unlocked = await derive(passphrase, salt);
      const envelope = await seal([], unlocked.key, salt);
      const response = await fetch("/api/vault", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${unlocked.writeToken}`, "X-Veil-Setup": invite }, body: JSON.stringify({ envelope, revision: 0 }) });
      const result = await response.json() as { revision: number; error?: string }; if (!response.ok) throw new Error(result.error);
      if (generation !== epoch.current) return;
      setVault({ initialized: true, envelope, revision: result.revision }); credentials.current = unlocked;
      setTasks([]); setIsUnlocked(true); setInvite(""); setPassphrase(""); setConfirmation(""); setSaved(true); lastActivity.current = Date.now();
      setMessage("Your key is set. Only you know it. Add your first task.");
    } catch (e) { if (generation === epoch.current) setError(e instanceof Error ? e.message : "Setup failed. Try again."); }
    finally { if (generation === epoch.current) setBusy(false); }
  }
  async function save(next: Task[]) {
    if (!vault || !credentials.current || busy) return;
    setBusy(true); setError(""); setMessage(""); const generation = epoch.current; const auth = credentials.current;
    try {
      const envelope = await seal(next, auth.key, vault.envelope.salt);
      if (generation !== epoch.current) return;
      const response = await fetch("/api/vault", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${auth.writeToken}` }, body: JSON.stringify({ envelope, revision: vault.revision }) });
      const result = await response.json() as { revision: number; error?: string }; if (!response.ok) throw new Error(result.error);
      if (generation !== epoch.current) return;
      setTasks(next); setVault({ ...vault, envelope, revision: result.revision }); setSaved(true); setNewTask(""); setMessage("Saved as ciphertext.");
    } catch (e) {
      if (generation === epoch.current) { setTasks(next); setSaved(false); setError(e instanceof Error ? e.message : "Save failed. Retry before locking."); }
    } finally { if (generation === epoch.current) setBusy(false); }
  }
  function add(event: FormEvent) {
    event.preventDefault(); if (!newTask.trim()) return;
    if (tasks.length >= 500) { setError("The vault holds up to 500 tasks."); return; }
    void save([...tasks, { id: crypto.randomUUID(), title: newTask.trim(), done: false }]);
  }
  function safeLock() {
    if ((!saved || newTask.trim()) && !window.confirm("You have unsaved text. Locking clears it from this screen. Lock anyway?")) return;
    lock(); void load();
  }
  const setupMode = !!invite && !vault?.initialized;
  const chunks = vault?.envelope.ciphertext.match(/.{1,144}/g) || [];
  const done = tasks.filter(t => t.done).length;
  return <div className={isUnlocked ? "site-shell is-unlocked" : "site-shell"}>
    <header className="topbar"><a className="brand" href="/" aria-label="VEIL home"><span className="brand-mark"><Fingerprint size={25} strokeWidth={1.6} /></span><span>veil<span className="brand-period">.</span></span></a><div className="top-caption">A PERSONAL LIST IN PLAIN SIGHT</div><button className="text-button about-button" onClick={() => setAbout(true)}><Code2 size={17} /> Behind the cipher</button></header>
    <main>
      <div className="intro"><div><div className="eyebrow"><span className="tiny-square" /> PUBLIC VAULT / 001</div><h1>Public list.<br /><span>Private meaning.</span></h1><p>Everything is here. The meaning is yours to unlock.</p></div><div className={`access-stamp ${isUnlocked ? "open" : ""}`}><span>{isUnlocked ? <Unlock size={22} /> : <LockKeyhole size={22} />}</span><div><small>ACCESS STATE</small><strong>{isUnlocked ? "Decrypted locally" : "Encrypted"}</strong><span>{isUnlocked ? "Visible in your browser only" : "Visible to everyone. Readable with a key."}</span></div></div></div>
      <div className="workspace">
        <section className="list-panel" aria-label={isUnlocked ? "Your to-do list" : "Encrypted to-do list"}>
          <div className="panel-header"><div><span className="panel-number">01</span><h2>{isUnlocked ? "Your to-do list" : "The sealed list"}</h2></div><span className="chip">{isUnlocked ? `${tasks.length} TASK${tasks.length === 1 ? "" : "S"}` : "CIPHERTEXT"}</span></div>
          <div className="list-meta"><span>{isUnlocked ? `${done} complete · ${tasks.length - done} remaining` : "AES-256-GCM / AUTHENTICATED ENCRYPTION"}</span><span>{isUnlocked ? saved ? "ENCRYPTED & SAVED" : "UNSAVED CHANGES" : vault?.initialized ? `REVISION ${String(vault.revision).padStart(3, "0")}` : "ENCRYPTED PREVIEW"}</span></div>
          {isUnlocked ? <div className="task-area">
            <form className="add-task" onSubmit={add}><Plus size={20} /><input aria-label="New task" value={newTask} onChange={e => setNewTask(e.target.value)} placeholder="What needs doing?" maxLength={1000} disabled={busy} /><button disabled={busy || !newTask.trim()} type="submit">Add task</button></form>
            {tasks.length === 0 ? <div className="empty"><Check size={30} /><h3>A clear slate.</h3><p>Add a task. It will be encrypted before it leaves your browser.</p></div> : <ul className="tasks">{tasks.map((task, index) => <li key={task.id} className={task.done ? "complete" : ""}><button className="task-check" aria-label={`${task.done ? "Mark incomplete" : "Complete"}: ${task.title}`} aria-pressed={task.done} disabled={busy} onClick={() => void save(tasks.map(t => t.id === task.id ? { ...t, done: !t.done } : t))}>{task.done && <Check size={15} />}</button><span className="task-index">{String(index + 1).padStart(2, "0")}</span><span className="task-title">{task.title}</span><button className="delete-task" aria-label={`Delete: ${task.title}`} disabled={busy} onClick={() => { if (window.confirm("Delete this task?")) void save(tasks.filter(t => t.id !== task.id)); }}><Trash2 size={17} /></button></li>)}</ul>}
            {!saved && <button className="retry-save" disabled={busy} onClick={() => void save(tasks)}>Retry saving changes</button>}
          </div> : vault ? <div className="cipher-list">{chunks.slice(0, 8).map((chunk, index) => <div className="cipher-row" key={index}><div className="cipher-index">{String(index + 1).padStart(2, "0")}<LockKeyhole size={15} /></div><div className="cipher-content"><span className="block-label">ENCRYPTED BLOCK {String(index + 1).padStart(2, "0")}</span><code>{chunk}</code></div></div>)}{chunks.length > 8 && <p className="more-blocks">+ {chunks.length - 8} more encrypted blocks. Unlock to read the full list.</p>}</div> : <div className="loading-state">{error ? <button onClick={() => void load()}>Retry loading vault</button> : "Retrieving ciphertext…"}</div>}
          <div className="panel-footer"><ShieldCheck size={17} /><span>{isUnlocked ? "Changes are encrypted in your browser before saving." : "Task text and completion status are both encrypted."}</span></div>
        </section>
        <aside className="key-panel"><div className="panel-number">02 / {isUnlocked ? "PRIVATE SESSION" : setupMode ? "FIRST-TIME SETUP" : "KEY REQUIRED"}</div><div className="key-icon">{isUnlocked ? <Unlock size={28} strokeWidth={1.5} /> : <KeyRound size={28} strokeWidth={1.5} />}</div><h2>{isUnlocked ? "Only on this screen." : setupMode ? "Make it yours." : "Know the key?"}</h2><p>{isUnlocked ? "Your list is decrypted in this browser. Lock it when you're done." : setupMode ? "Choose the secret that unlocks your list. It never goes into the source code." : "Enter the secret to turn the ciphertext into a to-do list."}</p>
          {isUnlocked ? <button className="primary-button lock-button" onClick={safeLock} disabled={busy}><LockKeyhole size={17} /> Lock the vault</button> : <form onSubmit={setupMode ? setup : e => { e.preventDefault(); if (vault) void unlockWith(passphrase, vault); }}><label htmlFor="secret">{setupMode ? "Choose your secret key" : "Your secret key"}</label><div className="key-input"><KeyRound size={16} /><input id="secret" type="password" autoComplete="off" spellCheck={false} value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder={setupMode ? "At least 16 characters" : "Enter your key"} required maxLength={1024} disabled={busy || !vault} /></div>{setupMode && <><label htmlFor="confirm">Confirm your key</label><div className="key-input"><input id="confirm" type="password" autoComplete="off" value={confirmation} onChange={e => setConfirmation(e.target.value)} placeholder="Enter it again" required maxLength={1024} disabled={busy} /></div><p className="setup-note">Use a unique, long passphrase. Save it privately: there is no key recovery.</p></>}<button className="primary-button" type="submit" disabled={busy || !vault || !passphrase}>{busy ? "Working…" : setupMode ? "Create my private list" : "Decrypt list"}{!busy && <Unlock size={17} />}</button></form>}
          <div className="feedback" aria-live="polite">{error && <p className="error">{error}</p>}{message && <p className="success">{message}</p>}</div>{!vault?.initialized && !setupMode && <p className="preview-note">Owner setup is pending. The preview is real ciphertext with no public unlock key.</p>}<div className="key-detail"><span className="detail-dot" /><span>{isUnlocked ? "Auto-locks after 5 minutes of inactivity" : "Your secret stays in your browser"}</span></div><div className="key-bottom"><span>NO STORED KEY</span><span>NO PLAINTEXT AT REST</span></div>
        </aside>
      </div>
      <div className="principle-bar"><span className="bracket">[</span><p>Open source.<span> Closed to everyone without the key.</span></p><span className="bracket">]</span><a href="https://github.com/felimart2003/veil-encrypted-todo" target="_blank" rel="noopener noreferrer"><Code2 size={17} /> View the source<ArrowUpRight size={16} /></a></div>
    </main>
    <footer className="site-footer"><span>VEIL / A CYBERSECURITY PORTFOLIO EXPERIMENT</span><span>THE CODE IS PUBLIC. THE KEY IS YOURS.</span></footer>
    <dialog ref={aboutRef} className="about-dialog" onClose={() => setAbout(false)} onClick={e => { if (e.target === e.currentTarget) setAbout(false); }}><div className="dialog-top"><span className="eyebrow">BEHIND THE CIPHER</span><button aria-label="Close explanation" onClick={() => setAbout(false)}><X size={22} /></button></div><h2>Privacy by design.</h2><p>VEIL keeps a personal list publicly visible as ciphertext. Entering the right key decrypts it entirely in your browser.</p><dl><dt>01 / Derive</dt><dd>PBKDF2-SHA-256 runs 600,000 iterations with a random 128-bit salt. The result is split into an encryption key and a separate write credential.</dd><dt>02 / Encrypt</dt><dd>AES-256-GCM encrypts the complete list, including completion status, with a fresh 96-bit nonce on each save. Its authentication tag rejects a wrong key or modified ciphertext.</dd><dt>03 / Store</dt><dd>The server stores ciphertext, salt, nonce, revision, and a hash of the separate write credential. Your secret and encryption key never leave the browser.</dd></dl><h3>A quiet way in</h3><p>Use <code>#key=YOUR_URL_ENCODED_KEY</code> after the site address for automatic unlocking. The fragment is removed immediately and isn't sent in HTTP requests. Anyone who has that full link can read and edit your list; the key field is safer on shared devices.</p><h3>The honest limits</h3><p>This is a portfolio experiment, not an audited password manager. Ciphertext size and revisions are public. Weak secrets can be guessed offline. A compromised browser or modified site could capture your key. There is no recovery for a forgotten key.</p><a className="documentation-link" href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API" target="_blank" rel="noopener noreferrer">Read about the Web Crypto API<ArrowUpRight size={16} /></a></dialog>
  </div>;
}
