import React from 'react';

function Filters({ filters, filterOptions, onFilterChange, onClear }) {
    const handleChange = (key, value) => {
        onFilterChange(key, value === 'all' ? '' : value);
    };

    const severities = filterOptions.severities || [];
    const vendors = filterOptions.vendors || [];
    const techTypes = filterOptions.techTypes || [];
    // Source names come from the API so the options cannot drift out of sync
    // with the labels the fetchers actually write.
    const sources = filterOptions.sources || [];

    const hasActiveFilters = Boolean(
        filters.source || filters.severity || filters.startDate || filters.endDate
        || filters.vendor || filters.techType || filters.kevFlag || filters.search
    );

    return (
        <div className="filters-panel">
            <h3>Filters</h3>
            <div className="filters-row">
                <div className="filter-group">
                    <label htmlFor="filter-severity">Severity</label>
                    <select id="filter-severity" value={filters.severity} onChange={e => handleChange('severity', e.target.value)}>
                        <option value="">All</option>
                        {severities.map(s => (
                            <option key={s} value={s}>{s}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label htmlFor="filter-source">Source</label>
                    <select id="filter-source" value={filters.source} onChange={e => handleChange('source', e.target.value)}>
                        <option value="">All</option>
                        {sources.map(s => (
                            <option key={s} value={s}>{s}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label htmlFor="filter-vendor">Vendor</label>
                    <select id="filter-vendor" value={filters.vendor} onChange={e => handleChange('vendor', e.target.value)}>
                        <option value="">All</option>
                        {vendors.map(v => (
                            <option key={v} value={v}>{v}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label htmlFor="filter-tech">Technology</label>
                    <select id="filter-tech" value={filters.techType} onChange={e => handleChange('techType', e.target.value)}>
                        <option value="">All</option>
                        {techTypes.map(t => (
                            <option key={t} value={t}>{t}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label htmlFor="filter-start">Start Date</label>
                    <input id="filter-start" type="date" value={filters.startDate} onChange={e => handleChange('startDate', e.target.value)} />
                </div>

                <div className="filter-group">
                    <label htmlFor="filter-end">End Date</label>
                    <input id="filter-end" type="date" value={filters.endDate} onChange={e => handleChange('endDate', e.target.value)} />
                </div>

                <div className="filter-group">
                    <label htmlFor="filter-kev">Known Exploited</label>
                    <select id="filter-kev" value={filters.kevFlag} onChange={e => handleChange('kevFlag', e.target.value)}>
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
