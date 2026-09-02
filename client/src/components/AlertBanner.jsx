import React from 'react';

function AlertBanner({ alerts }) {
    return (
        <div className="alert-banner">
            <span className="alert-icon">🔔</span>
            <div className="alert-content">
                <div className="alert-title">Watchlist Alerts ({alerts.length})</div>
                {alerts.slice(0, 5).map((alert, i) => (
                    <div key={i} className="alert-message">
                        <strong>{alert.cve_id}</strong> — {alert.message}
                    </div>
                ))}
                {alerts.length > 5 && (
                    <div className="alert-message">...and {alerts.length - 5} more alerts</div>
                )}
            </div>
        </div>
    );
}

export default AlertBanner;
