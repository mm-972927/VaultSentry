import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';

export function useScans() {
  const [scans, setScans]   = useState([]);
  const [stats, setStats]   = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      const [s, st] = await Promise.all([api.getScans(), api.getStats()]);
      setScans(s);
      setStats(st);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 2500);
    return () => clearInterval(t);
  }, [fetchAll]);

  const submitScan = async (scanName, targetPath, requestedBy) => {
    await api.submitScan(scanName, targetPath, requestedBy);
    fetchAll();
  };

  const deleteScan = async (id) => {
    await api.deleteScan(id);
    setScans(prev => prev.filter(s => s.id !== id));
  };

  return { scans, stats, loading, error, submitScan, deleteScan };
}
