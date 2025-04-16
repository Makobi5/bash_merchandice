document.addEventListener('DOMContentLoaded', function() {
    // Initialize reporting functionality
    initReportingControls();
    
    // Initialize action buttons
    initActionButtons();
});

function initReportingControls() {
    const downloadButton = document.getElementById('download-report');
    const printButton = document.getElementById('print-report');
    const periodSelect = document.getElementById('report-period');
    
    // Download report
    downloadButton.addEventListener('click', function() {
        const period = periodSelect.value;
        downloadReport(period);
    });
    
    // Print report
    printButton.addEventListener('click', function() {
        const period = periodSelect.value;
        printReport(period);
    });
}

function downloadReport(period) {
    // Send request to backend to generate report
    fetch(`/api/reports/${period}`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (response.ok) {
            return response.blob();
        }
        throw new Error('Network response was not ok');
    })
    .then(blob => {
        // Create a download link and trigger it
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = `${period}_report_${getFormattedDate()}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    })
    .catch(error => {
        console.error('Error downloading report:', error);
        alert('Failed to download report. Please try again.');
    });
}

function printReport(period) {
    // Request a printable version of the report
    fetch(`/api/reports/${period}/print`, {
        method: 'GET'
    })
    .then(response => response.text())
    .then(html => {
        // Create a new window with the report HTML
        const printWindow = window.open('', '_blank');
        printWindow.document.write(html);
        printWindow.document.close();
        
        // Wait for content to load before printing
        printWindow.onload = function() {
            printWindow.print();
        };
    })
    .catch(error => {
        console.error('Error printing report:', error);
        alert('Failed to print report. Please try again.');
    });
}

function initActionButtons() {
    // View transaction buttons
    document.querySelectorAll('.btn-view').forEach(button => {
        button.addEventListener('click', function() {
            const transactionId = this.getAttribute('data-id');
            viewTransaction(transactionId);
        });
    });
    
    // Edit transaction buttons
    document.querySelectorAll('.btn-edit').forEach(button => {
        button.addEventListener('click', function() {
            const transactionId = this.getAttribute('data-id');
            editTransaction(transactionId);
        });
    });
}

function viewTransaction(id) {
    window.location.href = `/transactions/${id}`;
}

function editTransaction(id) {
    window.location.href = `/transactions/${id}/edit`;
}

function getFormattedDate() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}