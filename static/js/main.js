document.addEventListener('DOMContentLoaded', function() {
    // Initialize flash message dismissal
    initFlashMessages();
    
    // Initialize confirm dialogs
    initConfirmDialogs();
});

function initFlashMessages() {
    const flashMessages = document.querySelectorAll('.flash-message');
    
    flashMessages.forEach(message => {
        // Add close button
        const closeBtn = document.createElement('span');
        closeBtn.innerHTML = '&times;';
        closeBtn.className = 'close-btn';
        closeBtn.style.float = 'right';
        closeBtn.style.cursor = 'pointer';
        closeBtn.style.fontWeight = 'bold';
        closeBtn.onclick = function() {
            message.style.display = 'none';
        };
        
        message.prepend(closeBtn);
        
        // Auto close after 5 seconds
        setTimeout(() => {
            message.style.opacity = '0';
            setTimeout(() => {
                message.style.display = 'none';
            }, 500);
        }, 5000);
        
        // Add transition
        message.style.transition = 'opacity 0.5s ease';
    });
}

function initConfirmDialogs() {
    const confirmBtns = document.querySelectorAll('[data-confirm]');
    
    confirmBtns.forEach(btn => {
        btn.addEventListener('click', function(e) {
            const message = this.getAttribute('data-confirm') || 'Are you sure you want to perform this action?';
            
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

// Debounce function for search inputs
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}