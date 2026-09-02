import React, { useState, useEffect } from 'react';
import { getVulnerabilities, getFilterOptions, triggerFetch, getAlerts, getVulnerabilityCount } from './services/api';
import VulnerabilityTable from './components/VulnerabilityTable';
import Filters from './components/Filters';
import AlertBanner from './components/AlertBanner';

function App() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, total: 0, totalPages: 0 });
  const [loading, setLoading] = useState(true);
  const [fetching, setFetching] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [filterOptions, setFilterOptions] = useState({ severities: [], vendors: [], techTypes: [] });
  
  const [filters, setFilters] = useState({
    source: '',
    severity: '',
    startDate: '',
    endDate: '',
    vendor: '',
    techType: '',
    kevFlag: '',
    search: '',
  });
  
  const [sort, setSort] = useState({ sortBy: 'published_date', sortOrder: 'DESC' });

  const loadData = async (currentPage = pagination.page) => {
    setLoading(true);
    try {
      const result = await getVulnerabilities({
        ...filters,
        page: currentPage,
        perPage: 25,
        sortBy: sort.sortBy,
        sortOrder: sort.sortOrder,
      });
      setVulnerabilities(result.data || []);
      setPagination(result.pagination || { page: 1, total: 0, totalPages: 0 });
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
      setVulnerabilities([]);
    } finally {
      setLoading(false);
    }
  };

  const loadFilterOptions = async () => {
    try {
      const options = await getFilterOptions();
      setFilterOptions(options);
    } catch (err) {
      console.error('Failed to load filter options:', err);
    }
  };

  const loadAlerts = async () => {
    try {
      const result = await getAlerts(20);
      setAlerts(result.alerts || []);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    }
  };

  useEffect(() => {
    loadData();
    loadFilterOptions();
    loadAlerts();
  }, []);

  useEffect(() => {
    loadData(pagination.page);
  }, [filters, sort]);

  const handleRefresh = async () => {
    setFetching(true);
    try {
      await triggerFetch();
      await loadData();
      loadFilterOptions();
      loadAlerts();
    } catch (err) {
      console.error('Fetch failed:', err);
    } finally {
      setFetching(false);
    }
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const handleSort = (column) => {
    setSort(prev => ({
      sortBy: column,
      sortOrder: prev.sortBy === column && prev.sortOrder === 'DESC' ? 'ASC' : 'DESC',
    }));
  };

  const handlePageChange = (newPage) => {
    loadData(newPage);
  };

  return (
    <div className="dashboard">
      <div className="header">
        <h1>🛡️ Vulnerability Dashboard</h1>
        <button className="refresh-btn" onClick={handleRefresh} disabled={fetching}>
          {fetching ? 'Fetching...' : '⟳ Refresh Data'}
        </button>
      </div>

      <StatsBar total={pagination.total} />
      
      {alerts.length > 0 && (
        <AlertBanner alerts={alerts} />
      )}

      <div className="search-bar">
        <input
          type="text"
          placeholder="🔍 Search CVE ID, description, vendor, product..."
          value={filters.search}
          onChange={(e) => handleFilterChange('search', e.target.value)}
        />
      </div>

      <Filters
        filters={filters}
        filterOptions={filterOptions}
        onFilterChange={handleFilterChange}
        onClear={() => setFilters({
          source: '', severity: '', startDate: '', endDate: '',
          vendor: '', techType: '', kevFlag: '', search: '',
        })}
      />

      <VulnerabilityTable
        data={vulnerabilities}
        sort={sort}
        onSort={handleSort}
        pagination={pagination}
        onPageChange={handlePageChange}
        loading={loading}
      />
    </div>
  );
}

function StatsBar({ total }) {
  return (
    <div className="stats-bar">
      <div className="stat-card">
        <div className="stat-value">{total.toLocaleString()}</div>
        <div className="stat-label">Total Vulnerabilities</div>
      </div>
    </div>
  );
}

export default App;
