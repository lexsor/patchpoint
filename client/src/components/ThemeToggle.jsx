import React, { useCallback, useEffect, useState } from 'react';

const STORAGE_KEY = 'patchpoint-theme';
const DARK = 'dark';
const LIGHT = 'light';

/**
 * Read the theme already applied to <html> by the inline script in index.html.
 * That script is the single source of truth for the initial value, so this
 * component never re-decides it and cannot disagree with what is on screen.
 */
function currentTheme() {
    if (typeof document === 'undefined') return DARK;
    return document.documentElement.getAttribute('data-theme') === LIGHT ? LIGHT : DARK;
}

/**
 * Dark/light switch. Dark is the product default — no stored preference means
 * dark, regardless of the OS `prefers-color-scheme`. Choosing light stamps
 * data-theme on <html>, which swaps the token palette in styles.css.
 */
export default function ThemeToggle() {
    const [theme, setTheme] = useState(currentTheme);

    // Sync the DOM only. Storage is written by `toggle`, so simply loading the
    // page never records a preference the user did not express — "nothing
    // stored" keeps meaning "wants the default".
    useEffect(() => {
        const root = document.documentElement;

        if (theme === LIGHT) {
            root.setAttribute('data-theme', LIGHT);
        } else {
            root.removeAttribute('data-theme');
        }
        // Keep native widgets (select popups, date pickers, scrollbars) in step.
        root.style.colorScheme = theme;
    }, [theme]);

    const toggle = useCallback(() => {
        const next = theme === LIGHT ? DARK : LIGHT;
        setTheme(next);

        try {
            localStorage.setItem(STORAGE_KEY, next);
        } catch {
            // Private mode or blocked site data: the choice applies now but
            // does not survive a reload. Not worth surfacing.
        }
    }, [theme]);

    const switchingTo = theme === LIGHT ? DARK : LIGHT;

    return (
        <button
            type="button"
            className="theme-toggle"
            onClick={toggle}
            title={`Switch to ${switchingTo} theme`}
            aria-label={`Switch to ${switchingTo} theme`}
        >
            <span aria-hidden="true">{theme === LIGHT ? '☽' : '☀'}</span>
        </button>
    );
}
