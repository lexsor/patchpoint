import React, { useState, useEffect, useCallback, useRef } from 'react';
import { getVulnerabilities, getFilterOptions, triggerFetch, getAlerts } from './api';
import VulnerabilityTable from './components/VulnerabilityTable';
import Filters from './components/Filters';
import AlertBanner from './components/AlertBanner';

const PER_PAGE = 25;
const SEARCH_DEBOUNCE_MS = 300;

const EMPTY_FILTERS = {
  source: '',
  severity: '',
  startDate: '',
  endDate: '',
  vendor: '',
  techType: '',
  kevFlag: '',
  search: '',
};

const EMPTY_PAGINATION = { page: 1, perPage: PER_PAGE, total: 0, totalPages: 0 };

function App() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [pagination, setPagination] = useState(EMPTY_PAGINATION);
  const [loading, setLoading] = useState(true);
  const [fetching, setFetching] = useState(false);
  const [error, setError] = useState('');
  const [alerts, setAlerts] = useState([]);
  const [filterOptions, setFilterOptions] = useState({ severities: [], vendors: [], techTypes: [], sources: [] });

  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [sort, setSort] = useState({ sortBy: 'published_date', sortOrder: 'DESC' });
  const [page, setPage] = useState(1);
  // Bumped to force a reload when nothing about the query itself changed
  // (after a manual refresh brings in new rows).
  const [reloadToken, setReloadToken] = useState(0);

  // Text typed into the search box, debounced into `filters.search` so a
  // request is not issued on every keystroke.
  const [searchInput, setSearchInput] = useState('');

  const loadFilterOptions = useCallback(async () => {
    try {
      const options = await getFilterOptions();
      setFilterOptions({
        severities: options.severities || [],
        vendors: options.vendors || [],
        techTypes: options.techTypes || [],
        sources: options.sources || [],
      });
    } catch (err) {
      console.error('Failed to load filter options:', err);
    }
  }, []);

  const loadAlerts = useCallback(async () => {
    try {
      const result = await getAlerts(20);
      setAlerts(result.alerts || []);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => (prev.search === searchInput ? prev : { ...prev, search: searchInput }));
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchInput]);

  // Single source of truth for loading the table. Keyed on everything that
  // affects the query, so mounting does not fire a second redundant request.
  const requestId = useRef(0);
  useEffect(() => {
    const currentRequest = ++requestId.current;
    let cancelled = false;

    setLoading(true);
    getVulnerabilities({ ...filters, page, perPage: PER_PAGE, ...sort })
      .then((result) => {
        // Ignore a slow response that a newer request has already superseded.
        if (cancelled || currentRequest !== requestId.current) return;
        setVulnerabilities(result.data || []);
        setPagination(result.pagination || EMPTY_PAGINATION);
        setError('');
      })
      .catch((err) => {
        if (cancelled || currentRequest !== requestId.current) return;
        console.error('Failed to load vulnerabilities:', err);
        setVulnerabilities([]);
        setPagination(EMPTY_PAGINATION);
        setError('Could not load vulnerabilities. Is the API running?');
      })
      .finally(() => {
        if (!cancelled && currentRequest === requestId.current) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [filters, sort, page, reloadToken]);

  useEffect(() => {
    loadFilterOptions();
    loadAlerts();
  }, [loadFilterOptions, loadAlerts]);

  const handleRefresh = async () => {
    setFetching(true);
    setError('');
    try {
      const result = await triggerFetch();

      const failures = Object.entries(result.sources || {})
        .filter(([, s]) => s && s.error)
        .map(([name, s]) => `${name}: ${s.error}`);
      if (failures.length > 0) {
        setError(`Some sources failed — ${failures.join('; ')}`);
      }

      // Reset to page 1: new data changes what the first page contains.
      setPage(1);
      setReloadToken((n) => n + 1);
      loadFilterOptions();
      loadAlerts();
    } catch (err) {
      console.error('Fetch failed:', err);
      setError('Refresh failed. Check the server logs.');
    } finally {
      setFetching(false);
    }
  };

  // Any filter change invalidates the current page number — a filter applied
  // while on page 5 would otherwise land on an empty page.
  const handleFilterChange = (key, value) => {
    setPage(1);
    if (key === 'search') {
      setSearchInput(value);
      return;
    }
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const handleClearFilters = () => {
    setPage(1);
    setSearchInput('');
    setFilters(EMPTY_FILTERS);
  };

  const handleSort = (column) => {
    setPage(1);
    setSort((prev) => ({
      sortBy: column,
      sortOrder: prev.sortBy === column && prev.sortOrder === 'DESC' ? 'ASC' : 'DESC',
    }));
  };

  return (
    <div className="dashboard">
      <div className="header">
        <h1>🛡️ Patchpoint</h1>
        <button className="refresh-btn" onClick={handleRefresh} disabled={fetching}>
          {fetching ? 'Fetching...' : '⟳ Refresh Data'}
        </button>
      </div>

      <StatsBar total={pagination.total} />

      {error && <div className="error-banner">{error}</div>}

      {alerts.length > 0 && <AlertBanner alerts={alerts} />}

      <div className="search-bar">
        <input
          type="text"
          placeholder="🔍 Search CVE ID, description, vendor, product..."
          value={searchInput}
          onChange={(e) => handleFilterChange('search', e.target.value)}
        />
      </div>

      <Filters
        filters={filters}
        filterOptions={filterOptions}
        onFilterChange={handleFilterChange}
        onClear={handleClearFilters}
      />

      <VulnerabilityTable
        data={vulnerabilities}
        sort={sort}
        onSort={handleSort}
        pagination={pagination}
        onPageChange={setPage}
        loading={loading}
      />
    </div>
  );
}

function StatsBar({ total }) {
  return (
    <div className="stats-bar">
      <div className="stat-card">
        <div className="stat-value">{Number(total || 0).toLocaleString()}</div>
        <div className="stat-label">Total Vulnerabilities</div>
      </div>
    </div>
  );
}

export default App;
