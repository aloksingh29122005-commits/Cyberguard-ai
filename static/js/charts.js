// CyberGuard AI - shared chart helpers (Chart.js must be loaded before this file)

// Read a color from the CSS variables in style.css, so colors are defined in one place
function cssValue(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function setChartDefaults() {
  Chart.defaults.color = cssValue("--muted");
  Chart.defaults.borderColor = cssValue("--line");
  Chart.defaults.font.family = cssValue("--font");
}

function drawBarChart(canvasId, labels, counts) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  new Chart(canvas, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Scans",
        data: counts,
        backgroundColor: cssValue("--blue"),
        borderRadius: 4,
        maxBarThickness: 28,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 7 } },
        y: { beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}

function drawDoughnutChart(canvasId, labels, counts) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  const levelColors = {
    Safe: cssValue("--safe"),
    Low: cssValue("--low"),
    Medium: cssValue("--medium"),
    High: cssValue("--high"),
    Critical: cssValue("--critical"),
  };

  new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: counts,
        backgroundColor: labels.map((name) => levelColors[name]),
        borderColor: cssValue("--panel"),
        borderWidth: 3,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "68%",
      plugins: { legend: { display: false } },
    },
  });
}