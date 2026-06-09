export default function ResponsibleUsePage() {
  return (
    <main className="policy-band">
      <article className="policy-shell">
        <p className="eyebrow">Responsible use</p>
        <h1>Only scan apps you own or have permission to test.</h1>
        <p>
          VibeCheck is built for builders who want a fast pre-judging or pre-launch sanity check.
          It performs limited, read-only checks against public app surfaces and avoids collecting
          sensitive target content.
        </p>

        <h2>Allowed use</h2>
        <ul>
          <li>Scan your own deployed app.</li>
          <li>Scan an app when the owner has explicitly asked you to do so.</li>
          <li>Use the gated Supabase check only when you own the target or have authorization.</li>
        </ul>

        <h2>Not allowed</h2>
        <ul>
          <li>Do not scan apps you do not own or have permission to test.</li>
          <li>Do not use VibeCheck to exploit, mutate, brute force, bypass auth, or harvest data.</li>
          <li>Do not submit private-network, localhost, metadata, file, or non-http targets.</li>
        </ul>

        <h2>Contact</h2>
        <p>
          For removal requests, security concerns, or responsible disclosure coordination, contact
          the project owner through the public repository or hackathon profile.
        </p>
      </article>
    </main>
  );
}
