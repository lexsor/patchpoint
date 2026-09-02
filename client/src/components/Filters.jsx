import React from 'react';

function Filters({ filters, filterOptions, onFilterChange, onClear }) {
    const handleChange = (key, value) => {
        onFilterChange(key, value === 'all' ? '' : value);
    };

    const hasActiveFilters = filters.source || filters.severity || filters.startDate || filters.endDate || filters.vendor || filters.techType || filters.kevFlag !== '';

    return (
        <div className="filters-panel">
            <h3>Filters</h3>
            <div className="filters-row">
                <div className="filter-group">
                    <label>Severity</label>
                    <select value={filters.severity} onChange={e => handleChange('severity', e.target.value)}>
                        <option value="">All</option>
                        {filterOptions.severities.map(s => (
                            <option key={s} value={s}>{s}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label>Source</label>
                    <select value={filters.source} onChange={e => handleChange('source', e.target.value)}>
                        <option value="">All</option>
                        <option value="CISA KEV">CISA KEV</option>
                        <option value="NVD">NVD</option>
                        <option value="MITRE CVEW">MITRE CVEW</option>
                    </select>
                </div>

                <div className="filter-group">
                    <label>Vendor</label>
                    <select value={filters.vendor} onChange={e => handleChange('vendor', e.target.value)}>
                        <option value="">All</option>
                        {filterOptions.vendors.map(v => (
                            <option key={v} value={v}>{v}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label>Technology</label>
                    <select value={filters.techType} onChange={e => handleChange('techType', e.target.value)}>
                        <option value="">All</option>
                        {filterOptions.techTypes.map(t => (
                            <option key={t} value={t}>{t}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label>Start Date</label>
                    <input type="date" value={filters.startDate} onChange={e => handleChange('startDate', e.target.value)} />
                </div>

                <div className="filter-group">
                    <label>End Date</label>
                    <input type="date" value={filters.endDate} onChange={e => handleChange('endDate', e.target.value)} />
                </div>

                <div className="filter-group">
                    <label>Known Exploited</label>
                    <select value={filters.kevFlag} onChange={e => handleChange('kevFlag', e.target.value)}>
                        <option value="">All</option>
                        <option value="true">⚠ Yes</option>
                        <option value="false">No</option>
                    </select>
                </div>

                {hasActiveFilters && (
                    <button className="clear-filters-btn" onClick={onClear}>Clear All Filters</button>
                )}
            </div>
        </div>
    );
}

export default Filters;
