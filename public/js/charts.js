/* Vigil v1.0 — Chart.js Wrappers */
(function() {
  'use strict';

  var chartInstances = {};

  var defaultColors = {
    cyan: '#ff6b2b',
    orange: '#ef4444',
    purple: '#a78bfa',
    cyanDim: 'rgba(255, 107, 43, 0.15)',
    orangeDim: 'rgba(239, 68, 68, 0.15)',
    purpleDim: 'rgba(167, 139, 250, 0.15)',
    grid: 'rgba(255, 255, 255, 0.05)',
    text: '#8b8b92',
    textDim: '#52525a'
  };

  // Set Chart.js defaults for dark theme
  if (typeof Chart !== 'undefined') {
    Chart.defaults.color = defaultColors.text;
    Chart.defaults.borderColor = defaultColors.grid;
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;
    Chart.defaults.plugins.legend.labels.boxHeight = 6;
    Chart.defaults.plugins.tooltip.backgroundColor = '#121212';
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(255,255,255,0.08)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.titleFont = { family: "'JetBrains Mono', monospace", size: 11 };
    Chart.defaults.plugins.tooltip.bodyFont = { family: "'JetBrains Mono', monospace", size: 11 };
  }

  function getCanvas(canvasId) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    return canvas.getContext('2d');
  }

  window.destroyChart = function(canvasId) {
    if (chartInstances[canvasId]) {
      chartInstances[canvasId].destroy();
      delete chartInstances[canvasId];
    }
  };

  window.createLineChart = function(canvasId, labels, datasets, options) {
    destroyChart(canvasId);
    var ctx = getCanvas(canvasId);
    if (!ctx) return null;

    var colorPalette = [defaultColors.cyan, defaultColors.orange, defaultColors.purple];
    var bgPalette = [defaultColors.cyanDim, defaultColors.orangeDim, defaultColors.purpleDim];

    var chartDatasets = datasets.map(function(ds, i) {
      return Object.assign({
        borderColor: colorPalette[i % colorPalette.length],
        backgroundColor: bgPalette[i % bgPalette.length],
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
        tension: 0.4,
        fill: true
      }, ds);
    });

    var chart = new Chart(ctx, {
      type: 'line',
      data: { labels: labels, datasets: chartDatasets },
      options: Object.assign({
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        scales: {
          x: {
            grid: { color: defaultColors.grid, drawBorder: false },
            ticks: { color: defaultColors.textDim, maxTicksLimit: 8 }
          },
          y: {
            grid: { color: defaultColors.grid, drawBorder: false },
            ticks: { color: defaultColors.textDim },
            beginAtZero: true
          }
        },
        plugins: {
          legend: { display: datasets.length > 1 }
        }
      }, options || {})
    });

    chartInstances[canvasId] = chart;
    return chart;
  };

  window.createBarChart = function(canvasId, labels, data, options) {
    destroyChart(canvasId);
    var ctx = getCanvas(canvasId);
    if (!ctx) return null;

    var colors = data.map(function(_, i) {
      var palette = [defaultColors.cyan, defaultColors.orange, defaultColors.purple];
      return palette[i % palette.length];
    });

    var chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors.map(function(c) { return c + '33'; }),
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 4,
          barPercentage: 0.6
        }]
      },
      options: Object.assign({
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: defaultColors.textDim }
          },
          y: {
            grid: { color: defaultColors.grid, drawBorder: false },
            ticks: { color: defaultColors.textDim },
            beginAtZero: true
          }
        },
        plugins: {
          legend: { display: false }
        }
      }, options || {})
    });

    chartInstances[canvasId] = chart;
    return chart;
  };

  window.createDoughnutChart = function(canvasId, labels, data, options) {
    destroyChart(canvasId);
    var ctx = getCanvas(canvasId);
    if (!ctx) return null;

    var colors = [defaultColors.orange, defaultColors.orange + 'aa', defaultColors.purple, defaultColors.cyan];
    var bgColors = labels.map(function(_, i) { return colors[i % colors.length]; });

    var chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: bgColors,
          borderColor: 'transparent',
          borderWidth: 0,
          hoverOffset: 4
        }]
      },
      options: Object.assign({
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              padding: 16,
              usePointStyle: true,
              pointStyleWidth: 8,
              font: { size: 11 }
            }
          }
        }
      }, options || {})
    });

    chartInstances[canvasId] = chart;
    return chart;
  };

  window.createRadarChart = function(canvasId, labels, data, options) {
    destroyChart(canvasId);
    var ctx = getCanvas(canvasId);
    if (!ctx) return null;

    var chart = new Chart(ctx, {
      type: 'radar',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: defaultColors.cyanDim,
          borderColor: defaultColors.cyan,
          borderWidth: 2,
          pointBackgroundColor: defaultColors.cyan,
          pointRadius: 3
        }]
      },
      options: Object.assign({
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            grid: { color: defaultColors.grid },
            angleLines: { color: defaultColors.grid },
            pointLabels: { color: defaultColors.text, font: { size: 11 } },
            ticks: { display: false },
            beginAtZero: true
          }
        },
        plugins: {
          legend: { display: false }
        }
      }, options || {})
    });

    chartInstances[canvasId] = chart;
    return chart;
  };

})();
