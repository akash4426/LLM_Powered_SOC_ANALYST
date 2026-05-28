// src/pages/RagTest/RagTest.jsx
import { useState } from 'react';
import { ragTest } from '../../api/socApi';
import { Search, Database, Layers } from 'lucide-react';
import styles from './RagTest.module.css';

const SAMPLE_QUERIES = [
  'T1110 brute force SSH password spraying credential stuffing',
  'T1021 lateral movement SMB pass the hash remote services',
  'T1041 data exfiltration HTTPS large transfer upload',
  'T1486 ransomware encryption shadow copy deletion bcdedit',
  'T1003 mimikatz LSASS credential dumping pass the hash',
  'T1059 PowerShell obfuscation command scripting interpreter',
  'T1071 command and control C2 beaconing application layer',
  'T1562 defense evasion antivirus disable log clearing impair defenses',
  'T1548 privilege escalation UAC bypass token impersonation sudo',
  'T1018 reconnaissance network scanning port discovery enumeration',
];

export default function RagTest() {
  const [query, setQuery]   = useState('');
  const [k, setK]           = useState(5);
  const [loading, setLoading] = useState(false);
  const [result, setResult]  = useState(null);
  const [error, setError]    = useState('');

  const run = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const data = await ragTest(query, k);
      setResult(data);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Query failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.page}>
      <div className={styles.inner}>

        <div className={styles.header}>
          <div className={styles.headerIcon}>
            <Database size={22} color="var(--cyan)" strokeWidth={1.5} />
          </div>
          <div>
            <h1 className={styles.title}>MITRE ATT&CK RAG TEST</h1>
            <p className={styles.subtitle}>Direct semantic search against the ChromaDB vector database</p>
          </div>
        </div>

        {/* Sample queries */}
        <div className={styles.sampleSection}>
          <div className={styles.sampleLabel}>SAMPLE QUERIES</div>
          <div className={styles.samples}>
            {SAMPLE_QUERIES.map(q => (
              <button key={q} className={styles.sampleChip} onClick={() => setQuery(q)}>{q}</button>
            ))}
          </div>
        </div>

        {/* Query input */}
        <div className={styles.queryCard}>
          <div className={styles.inputRow}>
            <div className={styles.inputWrap}>
              <Search size={14} className={styles.inputIcon} />
              <input
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && run()}
                placeholder="Enter a threat query…"
                className={styles.input}
              />
            </div>
            <div className={styles.kWrap}>
              <label className={styles.kLabel}>K</label>
              <select value={k} onChange={e => setK(Number(e.target.value))} className={styles.kSelect}>
                {[1,2,3,4,5,6,8,10].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <button className={styles.runBtn} onClick={run} disabled={loading || !query.trim()}>
              {loading ? <span className={styles.spinner} /> : <Search size={14} />}
              {loading ? 'SEARCHING…' : 'SEARCH'}
            </button>
          </div>

          {error && <div className={styles.error}>{error}</div>}
        </div>

        {/* Results */}
        {result && (
          <div className={styles.results}>
            <div className={styles.resultsHeader}>
              <Layers size={13} color="var(--cyan)" />
              <span>
                {result.snippet_count} snippet{result.snippet_count !== 1 ? 's' : ''} retrieved from{' '}
                <strong>{result.rag_source}</strong>
              </span>
              <span className={styles.mmrBadge} title="Max-Marginal Relevance — results are relevant AND diverse">
                MMR
              </span>
              <span className={styles.queryEcho}>k={result.k}</span>
            </div>

            {result.rag_snippets?.map((snip, i) => (
              <div key={i} className={styles.snippet}>
                <div className={styles.snippetNum}>#{i + 1}</div>
                <div className={styles.snippetText}>{snip}</div>
              </div>
            ))}
          </div>
        )}

      </div>
    </div>
  );
}
