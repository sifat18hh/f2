
// Complete Facebook Style CSS Fix - Final Solution
console.log('🎨 Complete Facebook Style CSS Fix - Loading...');

function completelyApplyFacebookStyle() {
    console.log('🎯 Applying complete Facebook black theme to ALL elements...');
    
    // Complete CSS Reset and Application
    const completeCSS = `
        /* Complete Facebook Black Theme - Final Fix */
        *, *::before, *::after {
            color: #e4e6ea !important;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif !important;
            margin: 0 !important;
            padding: 0 !important;
            box-sizing: border-box !important;
        }
        
        html, body {
            background: #18191a !important;
            color: #e4e6ea !important;
            height: 100vh !important;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif !important;
            background-image: none !important;
        }
        
        .admin-container, .admin-header, .admin-sidebar, .admin-content {
            background: #18191a !important;
            color: #e4e6ea !important;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif !important;
        }
        
        .admin-header {
            background: #242526 !important;
            border-bottom: 1px solid #3e4042 !important;
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            right: 0 !important;
            height: 60px !important;
            z-index: 1000 !important;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.5) !important;
        }
        
        .admin-sidebar {
            background: #242526 !important;
            border-right: 1px solid #3e4042 !important;
            position: fixed !important;
            top: 60px !important;
            left: 0 !important;
            width: 280px !important;
            height: calc(100vh - 60px) !important;
            z-index: 999 !important;
        }
        
        .admin-content {
            background: #18191a !important;
            margin-left: 280px !important;
            margin-top: 60px !important;
            padding: 24px !important;
            min-height: calc(100vh - 60px) !important;
        }
        
        .admin-nav-item {
            color: #e4e6ea !important;
            background: transparent !important;
            padding: 12px 16px !important;
            border-radius: 8px !important;
            margin: 2px 8px !important;
            transition: all 0.2s ease !important;
            display: flex !important;
            align-items: center !important;
            gap: 16px !important;
            text-decoration: none !important;
        }
        
        .admin-nav-item:hover {
            background: #3a3b3c !important;
            color: #1877f2 !important;
        }
        
        .admin-nav-item.active {
            background: linear-gradient(135deg, #1877f2, #42a5f5) !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.5) !important;
        }
        
        div, span, p, h1, h2, h3, h4, h5, h6, a, label, td, th, li, section, article, aside, nav, header, footer, main {
            color: #e4e6ea !important;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif !important;
        }
        
        .stat-card, .settings-card, .ai-control-group, .analytics-card, .earnings-overview, .table-container, .dashboard-widget, .ai-system-status, .quick-actions, .upload-area, .upload-tab {
            background: #242526 !important;
            border: 1px solid #3e4042 !important;
            color: #e4e6ea !important;
            border-radius: 12px !important;
            padding: 24px !important;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.5) !important;
            margin-bottom: 24px !important;
        }
        
        .admin-btn, button {
            background: linear-gradient(135deg, #1877f2, #42a5f5) !important;
            color: #ffffff !important;
            border: none !important;
            padding: 16px 24px !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            cursor: pointer !important;
            transition: all 0.2s ease !important;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.5) !important;
            font-family: 'Inter', sans-serif !important;
        }
        
        input, textarea, select {
            background: #242526 !important;
            border: 1px solid #3e4042 !important;
            color: #e4e6ea !important;
            padding: 16px !important;
            border-radius: 8px !important;
            font-family: 'Inter', sans-serif !important;
            width: 100% !important;
            box-sizing: border-box !important;
        }
        
        .admin-table, table {
            background: #242526 !important;
            color: #e4e6ea !important;
            width: 100% !important;
            border-collapse: collapse !important;
        }
        
        .admin-table th, .admin-table td, th, td {
            color: #e4e6ea !important;
            border-bottom: 1px solid #3e4042 !important;
            padding: 16px !important;
            text-align: left !important;
            background: #242526 !important;
        }
    `;
    
    // Remove any existing styles
    const existingStyles = document.querySelectorAll('#complete-facebook-fix');
    existingStyles.forEach(style => style.remove());
    
    // Inject complete CSS
    const style = document.createElement('style');
    style.id = 'complete-facebook-fix';
    style.textContent = completeCSS;
    document.head.appendChild(style);
    
    // Force apply styles to all elements
    document.querySelectorAll('*').forEach(element => {
        if (element.tagName !== 'STYLE' && element.tagName !== 'SCRIPT') {
            element.style.color = '#e4e6ea';
            element.style.fontFamily = "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif";
            
            // Apply container styles
            if (element.classList.contains('admin-container') || 
                element.classList.contains('admin-content') ||
                element.tagName === 'BODY' || 
                element.tagName === 'HTML') {
                element.style.background = '#18191a';
            }
            
            // Apply header/sidebar styles
            if (element.classList.contains('admin-header') || 
                element.classList.contains('admin-sidebar')) {
                element.style.background = '#242526';
                element.style.border = '1px solid #3e4042';
            }
            
            // Apply card styles
            if (element.classList.contains('stat-card') ||
                element.classList.contains('settings-card') ||
                element.classList.contains('table-container') ||
                element.classList.contains('dashboard-widget') ||
                element.classList.contains('ai-system-status') ||
                element.classList.contains('quick-actions') ||
                element.classList.contains('upload-area')) {
                element.style.background = '#242526';
                element.style.border = '1px solid #3e4042';
                element.style.borderRadius = '12px';
                element.style.padding = '24px';
            }
            
            // Apply button styles
            if (element.classList.contains('admin-btn') || element.tagName === 'BUTTON') {
                if (!element.classList.contains('exclude-theme')) {
                    element.style.background = 'linear-gradient(135deg, #1877f2, #42a5f5)';
                    element.style.color = '#ffffff';
                    element.style.border = 'none';
                }
            }
            
            // Apply input styles
            if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA' || element.tagName === 'SELECT') {
                element.style.background = '#242526';
                element.style.border = '1px solid #3e4042';
                element.style.color = '#e4e6ea';
            }
        }
    });
    
    console.log('✅ Complete Facebook black theme applied to ALL elements');
}

// Apply immediately
completelyApplyFacebookStyle();

// Apply on DOM ready
document.addEventListener('DOMContentLoaded', completelyApplyFacebookStyle);

// Apply continuously
setInterval(completelyApplyFacebookStyle, 1000);

// Apply on any interaction
document.addEventListener('click', () => setTimeout(completelyApplyFacebookStyle, 50));
document.addEventListener('scroll', () => setTimeout(completelyApplyFacebookStyle, 50));

// Make globally available
window.completelyApplyFacebookStyle = completelyApplyFacebookStyle;

console.log('✅ Complete Facebook Style CSS Fix Script Loaded');
