// CyberGuard AI - draws the dashboard charts with the numbers Flask put into the page

const dashboardDataElement = document.getElementById("dashboard-data");

if (dashboardDataElement) {
  if (typeof Chart === "undefined") {
    // Chart.js comes from the internet. If it did not load, say so instead of showing empty boxes.
    document.querySelectorAll(".chart-box").forEach((box) => {
      box.textContent = "The chart could not load. Check your internet connection and refresh.";
    });
  } else {
    const dashboardData = JSON.parse(dashboardDataElement.textContent);
    setChartDefaults();
    drawBarChart("activityChart", dashboardData.activity.labels, dashboardData.activity.counts);
    drawDoughnutChart("levelChart", dashboardData.distribution.labels, dashboardData.distribution.counts);
  }
}