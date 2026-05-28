// src/App.jsx
import { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import Topbar from './components/Topbar/Topbar';
import Login from './pages/Login/Login';
import Investigate from './pages/Investigate/Investigate';
import RagTest from './pages/RagTest/RagTest';
import styles from './App.module.css';

function AppShell() {
  const { token, loading } = useAuth();
  const [page, setPage] = useState('investigate');

  if (loading) {
    return (
      <div className={styles.splash}>
        <div className={styles.splashSpinner} />
        <div className={styles.splashText}>INITIALIZING SOC ANALYST…</div>
      </div>
    );
  }

  if (!token) return <Login />;

  const renderPage = () => {
    switch (page) {
      case 'investigate': return <Investigate />;
      case 'ragtest':     return <RagTest />;
      default:            return <Investigate />;
    }
  };

  return (
    <div className={styles.app}>
      <Topbar currentPage={page} onNavigate={setPage} />
      <div className={styles.content}>
        {renderPage()}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppShell />
    </AuthProvider>
  );
}
