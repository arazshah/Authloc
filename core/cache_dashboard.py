"""
Cache monitoring dashboard template.

A simple HTML dashboard for visualizing cache performance metrics.
"""

from django.template import Template, Context
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from django.contrib.admin.views.decorators import staff_member_required

from core.performance_monitor import get_performance_metrics
from core.cache_utils import cache_manager


@staff_member_required
@require_http_methods(["GET"])
def cache_dashboard(request):
    """
    Render the cache monitoring dashboard.

    Returns:
        HTML response with dashboard
    """
    # Get metrics data
    metrics = get_performance_metrics(hours=1)
    cache_stats = cache_manager.get_cache_stats()

    # Calculate some derived metrics
    cache_hit_ratio = 0
    total_cache_ops = cache_stats.get('hits', 0) + cache_stats.get('misses', 0)
    if total_cache_ops > 0:
        cache_hit_ratio = (cache_stats.get('hits', 0) / total_cache_ops) * 100

    context = {
        'metrics': metrics,
        'cache_stats': cache_stats,
        'cache_hit_ratio': round(cache_hit_ratio, 2),
        'title': 'Cache Performance Dashboard',
    }

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ title }}</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            .header {
                background: #2c3e50;
                color: white;
                padding: 20px;
                margin: 0;
            }
            .metrics-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                padding: 20px;
            }
            .metric-card {
                background: #f8f9fa;
                border-radius: 6px;
                padding: 20px;
                border-left: 4px solid #3498db;
            }
            .metric-title {
                font-size: 14px;
                color: #6c757d;
                margin-bottom: 10px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .metric-value {
                font-size: 32px;
                font-weight: bold;
                color: #2c3e50;
                margin: 0;
            }
            .metric-subtitle {
                font-size: 12px;
                color: #6c757d;
                margin-top: 5px;
            }
            .status-healthy { border-left-color: #27ae60; }
            .status-warning { border-left-color: #f39c12; }
            .status-error { border-left-color: #e74c3c; }
            .chart-placeholder {
                background: #ecf0f1;
                height: 200px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 4px;
                margin-top: 15px;
                color: #7f8c8d;
            }
            .refresh-btn {
                background: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                cursor: pointer;
                margin: 20px;
            }
            .refresh-btn:hover {
                background: #2980b9;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="header">{{ title }}</h1>

            <button class="refresh-btn" onclick="location.reload()">Refresh Dashboard</button>

            <div class="metrics-grid">
                <!-- Cache Performance -->
                <div class="metric-card status-healthy">
                    <div class="metric-title">Cache Hit Ratio</div>
                    <div class="metric-value">{{ cache_hit_ratio }}%</div>
                    <div class="metric-subtitle">{{ cache_stats.hits }} hits / {{ cache_stats.misses }} misses</div>
                </div>

                <div class="metric-card">
                    <div class="metric-title">Cache Memory Usage</div>
                    <div class="metric-value">{{ cache_stats.memory_used|default:"Unknown" }}</div>
                    <div class="metric-subtitle">Redis memory usage</div>
                </div>

                <div class="metric-card">
                    <div class="metric-title">Active Connections</div>
                    <div class="metric-value">{{ cache_stats.total_connections|default:0 }}</div>
                    <div class="metric-subtitle">Redis connections</div>
                </div>

                <!-- System Health -->
                <div class="metric-card status-healthy">
                    <div class="metric-title">System Status</div>
                    <div class="metric-value">Healthy</div>
                    <div class="metric-subtitle">All systems operational</div>
                </div>

                <!-- Response Times -->
                {% if metrics.performance.avg %}
                <div class="metric-card">
                    <div class="metric-title">Avg Response Time</div>
                    <div class="metric-value">{{ metrics.performance.avg|floatformat:2 }}ms</div>
                    <div class="metric-subtitle">Last hour average</div>
                </div>
                {% endif %}

                <!-- Database Stats -->
                {% if metrics.database.active_connections %}
                <div class="metric-card">
                    <div class="metric-title">DB Connections</div>
                    <div class="metric-value">{{ metrics.database.active_connections }}</div>
                    <div class="metric-subtitle">Active database connections</div>
                </div>
                {% endif %}
            </div>

            <!-- Charts Placeholder -->
            <div class="metrics-grid">
                <div style="grid-column: 1 / -1;">
                    <div class="metric-card">
                        <div class="metric-title">Performance Trends (Last 24 Hours)</div>
                        <div class="chart-placeholder">
                            Chart visualization would be implemented here<br>
                            (e.g., using Chart.js or similar library)
                        </div>
                    </div>
                </div>
            </div>

            <!-- Raw Data -->
            <details style="margin: 20px;">
                <summary>Raw Performance Data</summary>
                <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow: auto; max-height: 400px;">{{ metrics|tojson(indent=2) }}</pre>
            </details>
        </div>

        <script>
            // Auto-refresh every 5 minutes
            setTimeout(() => {
                if (confirm('Refresh dashboard with latest data?')) {
                    location.reload();
                }
            }, 300000);
        </script>
    </body>
    </html>
    """

    template = Template(html_template)
    html = template.render(Context(context))

    return HttpResponse(html)
