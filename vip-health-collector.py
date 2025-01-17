import os
import json
import logging
from datetime import datetime, timedelta
import threading
import time
from typing import Dict, Any, List, Optional

from flask import Flask, jsonify
import requests
from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vip-health-collector')
app = Flask(__name__)
collector = None


class VIPHealthCollector:
    def __init__(self, prometheus_url: str, clickhouse_host: str):
        self.prometheus_url = prometheus_url
        self.pool_cache = {}  # Add cache for pool names
        self.clickhouse_client = Client(
            host=clickhouse_host,
            port=9000,
            user='default',
            password='',
            database='vip_health',
            secure=False,
            verify=False
        )
        self._start_collection_thread()
        logger.info("Initialized collector with Prometheus URL: %s and ClickHouse host: %s" %
                   (prometheus_url, clickhouse_host))

    def _start_collection_thread(self):
        """Start background collection thread"""
        thread = threading.Thread(target=self._collection_worker, daemon=True)
        thread.start()
        logger.info("Started background collection thread")

    def _collection_worker(self):
        """Background worker to periodically collect VIP health scores"""
        while True:
            try:
                self.collect_all_vips()
            except Exception as e:
                logger.error("Error in collection worker: %s" % e)
            time.sleep(60)  # Wait 60 seconds before next collection

    def get_pool_name(self, vip_name: str) -> Optional[str]:
        """Get pool name from VIP info"""
        try:
            # Check cache first
            if vip_name in self.pool_cache:
                return self.pool_cache[vip_name]

            # Ensure VIP name starts with /
            if not vip_name.startswith('/'):
                vip_name = '/' + vip_name

            # Use exact working query format
            query = 'f5_virtual_server_info%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D'
            url = "%s/api/v1/query?query=%s" % (self.prometheus_url, query)

            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            if data['status'] == 'success' and data['data']['result']:
                pool_name = data['data']['result'][0]['metric'].get('f5_pool_name')
                self.pool_cache[vip_name] = pool_name  # Cache the result
                return pool_name
            return None

        except Exception as e:
            logger.error("Error getting pool name for VIP %s: %s" % (vip_name, e))
            raise

    def _get_metric_value(self, metric_data: Dict, default: float = 0.0) -> float:
        """Safely extract metric value from Prometheus response"""
        try:
            if not metric_data or 'data' not in metric_data:
                return default
            result = metric_data.get('data', {}).get('result', [])
            if not result:
                return default
            return float(result[0]['value'][1])
        except (IndexError, KeyError, TypeError, ValueError):
            return default

    def get_vip_metrics(self, vip_name: str) -> Dict[str, Any]:
        """Collect all relevant metrics for a VIP"""
        try:
            # Ensure VIP name starts with /
            if not vip_name.startswith('/'):
                vip_name = '/' + vip_name

            # Get pool name first
            pool_name = self.get_pool_name(vip_name)
            if not pool_name:
                logger.info("No pool found for VIP %s, will check for iRules", vip_name)

            metrics = {}
            metric_queries = {
                # Basic availability metrics
                'availability': 'f5_virtual_server_availability_ratio%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'enabled': 'f5_virtual_server_enabled_ratio%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'cpu_utilization': 'f5_virtual_server_cpu_utilization_5s%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',

                # Connection metrics
                'current_connections': 'f5_virtual_server_clientside_connection_count%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'connection_duration': 'f5_virtual_server_clientside_connection_duration_mean_milliseconds%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'connection_evicted': 'f5_virtual_server_clientside_connection_evicted_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'connection_slow_killed': 'f5_virtual_server_clientside_connection_slow_killed_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',

                # iRule metrics
                'irule_enabled': 'f5_virtual_server_rule_enabled_ratio%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'irule_executions': 'f5_rule_executions_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'irule_failures': 'f5_rule_failures_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'irule_aborts': 'f5_rule_aborts_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',

                # HTTP metrics
                'http_5xx_responses': 'f5_virtual_server_profile_http_responses_by_status_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22,http_status_range%3D%225xx%22%7D',
                'http_4xx_responses': 'f5_virtual_server_profile_http_responses_by_status_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22,http_status_range%3D%224xx%22%7D',

                # SSL metrics
                'ssl_handshake_failures': 'f5_virtual_server_profile_client_ssl_handshake_failures_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'ssl_secure_handshakes': 'f5_virtual_server_profile_client_ssl_secure_handshakes_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',

                # Traffic metrics
                'bytes_in': 'f5_virtual_server_clientside_bytes_in_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'bytes_out': 'f5_virtual_server_clientside_bytes_out_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'packets_in': 'f5_virtual_server_packets_in_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'packets_out': 'f5_virtual_server_packets_out_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',

                # DDoS protection metrics
                'syncookie_accepts': 'f5_virtual_server_syncookie_accepts_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'syncookie_rejects': 'f5_virtual_server_syncookie_rejects_total%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D'
            }

            # Add pool metrics only if pool exists
            if pool_name:
                pool_metrics = {
                    'pool_availability': 'f5_pool_availability_ratio%7Bf5_pool_name%3D%22' + pool_name + '%22,availability_state%3D%22available%22%7D',
                    'pool_member_availability': 'f5_pool_member_availability_ratio%7Bf5_pool_name%3D%22' + pool_name + '%22,availability_state%3D%22available%22%7D',
                    'pool_member_count': 'f5_pool_member_count%7Bf5_pool_name%3D%22' + pool_name + '%22,active_state%3D%22active%22%7D',
                }
                metric_queries.update(pool_metrics)

            for metric_name, query in metric_queries.items():
                url = "%s/api/v1/query?query=%s" % (self.prometheus_url, query)
                response = requests.get(url)
                response.raise_for_status()
                metrics[metric_name] = response.json()

            return metrics

        except Exception as e:
            logger.error("Error collecting metrics for VIP %s: %s", vip_name, e)
            raise

    def get_historical_metrics(self, vip_name: str) -> Dict[str, Any]:
        """Get historical metrics from ClickHouse for anomaly detection"""
        try:
            # Get metrics from the last 7 days
            query = """
            SELECT
                toDate(timestamp) as date,
                avg(total_score) as total_score,
                avg(availability_score) as availability_score,
                avg(performance_score) as performance_score,
                avg(pool_health_score) as pool_health_score,
                avg(response_health_score) as response_health_score,
                avg(ssl_health_score) as ssl_health_score,
                avg(connection_quality_score) as connection_quality_score,
                avg(ddos_protection_score) as ddos_protection_score,
                avg(cpu_utilization) as cpu_utilization,
                avg(current_connections) as current_connections,
                avg(connection_duration) as connection_duration
            FROM vip_health.health_scores
            WHERE vip_name = %(vip_name)s
            AND timestamp >= now() - INTERVAL 7 DAY
            GROUP BY date
            ORDER BY date DESC
            """
            
            result = self.clickhouse_client.execute(
                query,
                {'vip_name': vip_name}
            )

            # Convert to dictionary with dates as keys
            historical_data = {}
            for row in result:
                date_str = row[0].strftime('%Y-%m-%d')
                historical_data[date_str] = {
                    'total_score': float(row[1]),
                    'availability_score': float(row[2]),
                    'performance_score': float(row[3]),
                    'pool_health_score': float(row[4]),
                    'response_health_score': float(row[5]),
                    'ssl_health_score': float(row[6]),
                    'connection_quality_score': float(row[7]),
                    'ddos_protection_score': float(row[8]),
                    'cpu_utilization': float(row[9]),
                    'current_connections': float(row[10]),
                    'connection_duration': float(row[11])
                }
            
            return historical_data

        except Exception as e:
            logger.error(f"Error getting historical metrics for VIP {vip_name}: {e}")
            raise

    def calculate_anomalies(self, current_metrics: Dict[str, Any], historical_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate anomalies considering iRule operation"""
        try:
            today = datetime.now().strftime('%Y-%m-%d')
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            
            # Check if operating on iRules - with safe value extraction
            irule_only = (
                current_metrics.get('irule_enabled', False) and
                isinstance(current_metrics.get('pool_health_score'), (int, float)) and
                float(current_metrics.get('pool_health_score', 0)) < 50 and
                isinstance(current_metrics.get('irule_status', {}).get('health'), (int, float)) and
                float(current_metrics.get('irule_status', {}).get('health', 0)) > 80
            )

            # Get the last 7 days of data (excluding today)
            seven_day_data = {}
            for date, metrics in historical_data.items():
                if date != today and isinstance(metrics, dict):
                    for metric, value in metrics.items():
                        if not isinstance(value, (int, float)):
                            continue
                        if metric not in seven_day_data:
                            seven_day_data[metric] = []
                        seven_day_data[metric].append(float(value))

            # Calculate seven-day averages
            seven_day_averages = {}
            for metric, values in seven_day_data.items():
                if values:  # Only calculate if we have historical data
                    seven_day_averages[metric] = sum(values) / len(values)

            anomalies = {
                'day_over_day': [],
                'seven_day': [],
                'metrics': {}
            }

            # Define which metrics to check based on operating mode
            base_metrics = [
                'total_score', 'availability_score', 'performance_score',
                'response_health_score', 'ssl_health_score',
                'connection_quality_score', 'ddos_protection_score',
                'cpu_utilization', 'current_connections',
                'connection_duration'
            ]

            # Add iRule-specific metrics if using iRules
            irule_metrics = [
                'irule_executions', 'irule_failures', 'irule_aborts',
                'irule_failure_rate'
            ] if irule_only else []

            # Add pool metrics only if not in iRule-only mode
            pool_metrics = [] if irule_only else ['pool_health_score']

            metrics_to_check = base_metrics + irule_metrics + pool_metrics

            for metric in metrics_to_check:
                # Safe value extraction with type checking
                metric_value = current_metrics.get(metric)
                if isinstance(metric_value, dict):
                    # If it's a dict, try to get a specific value (adjust based on your data structure)
                    current_value = 0.0
                elif isinstance(metric_value, (int, float)):
                    current_value = float(metric_value)
                else:
                    current_value = 0.0

                metric_anomalies = {
                    'current_value': current_value,
                    'day_over_day': None,
                    'seven_day': None
                }

                threshold = (
                    50 if metric in ['irule_failures', 'irule_aborts', 'irule_failure_rate'] else
                    35 if metric in ['cpu_utilization', 'current_connections'] else
                    20  # Default threshold
                )

                # Day-over-day comparison
                if yesterday in historical_data:
                    yesterday_data = historical_data[yesterday].get(metric)
                    if isinstance(yesterday_data, (int, float)):
                        yesterday_value = float(yesterday_data)
                    else:
                        yesterday_value = 0.0

                    if yesterday_value != 0:  # Avoid division by zero
                        day_deviation = ((current_value - yesterday_value) / yesterday_value) * 100
                        metric_anomalies['day_over_day'] = {
                            'value': yesterday_value,
                            'deviation': round(day_deviation, 2)
                        }
                        if abs(day_deviation) > threshold:
                            anomalies['day_over_day'].append({
                                'metric': metric,
                                'current_value': current_value,
                                'comparison_value': yesterday_value,
                                'deviation': round(day_deviation, 2)
                            })

                # Seven-day comparison
                if metric in seven_day_averages:
                    avg_value = float(seven_day_averages[metric])
                    if avg_value != 0:  # Avoid division by zero
                        week_deviation = ((current_value - avg_value) / avg_value) * 100
                        metric_anomalies['seven_day'] = {
                            'value': avg_value,
                            'deviation': round(week_deviation, 2)
                        }
                        if abs(week_deviation) > threshold:
                            anomalies['seven_day'].append({
                                'metric': metric,
                                'current_value': current_value,
                                'comparison_value': avg_value,
                                'deviation': round(week_deviation, 2)
                            })

                anomalies['metrics'][metric] = metric_anomalies

            # Add operating mode context
            anomalies['context'] = {
                'mode': 'irule_only' if irule_only else 'normal',
                'irule_status': current_metrics.get('irule_status', {}),
                'pool_health': float(current_metrics.get('pool_health_score', 0))
            }

            return anomalies

        except Exception as e:
            logger.error("Error calculating anomalies: %s", e)
            raise
    def calculate_health_score(self, metrics: Dict[str, Any], vip_name: str = None) -> Dict[str, Any]:
        """Calculate comprehensive health score with iRule handling"""
        scores = {}
        messages = []
        weights = {
            'availability': 0.20,
            'performance': 0.15,
            'pool_health': 0.20,
            'response_health': 0.15,
            'ssl_health': 0.10,
            'connection_quality': 0.10,
            'ddos_protection': 0.10
        }

        try:
            # First check iRule status
            irule_enabled = False
            irule_active = False
            irule_health = 100
            irule_data = metrics.get('irule_enabled', {}).get('data', {}).get('result', [])
            
            if irule_data:
                for rule in irule_data:
                    if float(rule['value'][1]) == 1:
                        irule_enabled = True
                        irule_executions = sum(float(metric['value'][1]) for metric in 
                            metrics.get('irule_executions', {}).get('data', {}).get('result', []))
                        irule_failures = sum(float(metric['value'][1]) for metric in 
                            metrics.get('irule_failures', {}).get('data', {}).get('result', []))
                        irule_aborts = sum(float(metric['value'][1]) for metric in 
                            metrics.get('irule_aborts', {}).get('data', {}).get('result', []))
                        
                        if irule_executions > 0:
                            irule_active = True
                            failure_rate = (irule_failures + irule_aborts) / irule_executions
                            if failure_rate > 0.20:
                                irule_health -= min(50, failure_rate * 100)
                                messages.append(f"High iRule failure rate: {failure_rate:.1%}")
                            else:
                                messages.append(f"iRule performing normally: {failure_rate:.1%} failure rate")
                        break

            # Check VIP availability
            critical_failure = False
            avail_data = metrics.get('availability', {}).get('data', {}).get('result', [])
            if avail_data:
                for state in avail_data:
                    availability_state = state['metric'].get('availability_state')
                    value = float(state['value'][1])
                    if value == 1:
                        scores['availability_state'] = availability_state
                        if availability_state == 'unknown':
                            weights.pop('availability')
                            messages.append("An appropriate health monitor is necessary to determine availability health")
                        else:
                            scores['availability'] = 100 if availability_state == 'available' else 0
                            if availability_state != 'available' or scores['availability'] == 0:
                                # Only mark as critical if no working iRule
                                if not (irule_enabled and irule_active and irule_health > 80):
                                    critical_failure = True
                                    messages.append("VIP is not available and no working iRule")
                        break

            # Pool Health Check - modified to consider iRules
            pool_health = 100
            pool_data = metrics.get('pool_availability', {}).get('data', {}).get('result', [])
            pool_member_data = metrics.get('pool_member_availability', {}).get('data', {}).get('result', [])

            if pool_data and pool_member_data:
                available_members = sum(1 for member in pool_member_data
                                     if float(member['value'][1]) == 1)
                total_members = len(pool_member_data)
                
                if total_members > 0:
                    member_ratio = available_members / total_members
                    pool_health = float(pool_data[0]['value'][1]) * 100 * member_ratio
                    
                    if available_members < total_members:
                        messages.append(f"Only {available_members} of {total_members} pool members available")
                    
                    if available_members == 0:
                        if irule_enabled and irule_active and irule_health > 80:
                            messages.append("No available pool members, but iRule is handling traffic")
                            pool_health = 85  # Good but not perfect when relying on iRule
                        else:
                            critical_failure = True
                            messages.append("No pool members available and no working iRule")
            elif not pool_data and irule_enabled and irule_active:
                messages.append("Operating on iRule only (no pool configured)")
                pool_health = 90 if irule_health > 80 else irule_health
                # Adjust weights for iRule-only operation
                weights['pool_health'] = 0.10
                weight_diff = 0.10 / (len(weights) - 1)
                for key in weights:
                    if key != 'pool_health':
                        weights[key] += weight_diff
            elif not pool_data and not irule_enabled:
                critical_failure = True
                messages.append("No pool configured and no iRule enabled")

            scores['pool_health'] = pool_health

            # Performance Score (15% of total)
            perf_score = 100
            cpu_data = metrics.get('cpu_utilization', {}).get('data', {}).get('result', [])
            if cpu_data:
                cpu_util = float(cpu_data[0]['value'][1])
                if cpu_util > 90:
                    perf_score -= 30
                    messages.append(f"High CPU utilization: {cpu_util:.1f}%")
                elif cpu_util > 75:
                    perf_score -= 15
                    messages.append(f"Elevated CPU utilization: {cpu_util:.1f}%")

            scores['performance'] = max(0, perf_score)

            # Response Health Score (15% of total)
            http_score = 100
            error_details = {}

            # Check 5xx errors
            http_5xx = metrics.get('http_5xx_responses', {}).get('data', {}).get('result', [])
            if http_5xx:
                error_5xx_count = float(http_5xx[0]['value'][1])
                if error_5xx_count > 0:
                    penalty = min(50, error_5xx_count * 10)
                    http_score -= penalty
                    error_details['5xx_errors'] = {
                        'count': error_5xx_count,
                        'penalty': penalty
                    }
                    messages.append(f"Detected {error_5xx_count} 5xx errors (-{penalty} points)")

            scores['response_health'] = max(0, http_score)

            # Connection Quality Score (10% of total)
            conn_score = 100
            conn_evicted = metrics.get('connection_evicted', {}).get('data', {}).get('result', [])
            conn_slow_killed = metrics.get('connection_slow_killed', {}).get('data', {}).get('result', [])

            if conn_evicted:
                evicted = float(conn_evicted[0]['value'][1])
                if evicted > 0:
                    penalty = min(40, evicted * 5)
                    conn_score -= penalty
                    messages.append(f"Connections being evicted: {evicted} (-{penalty} points)")

            scores['connection_quality'] = max(0, conn_score)

            # DDoS Protection Score
            ddos_score = 100
            syncookie_accepts = metrics.get('syncookie_accepts', {}).get('data', {}).get('result', [])
            syncookie_rejects = metrics.get('syncookie_rejects', {}).get('data', {}).get('result', [])

            if syncookie_accepts and syncookie_rejects:
                accepts = float(syncookie_accepts[0]['value'][1])
                rejects = float(syncookie_rejects[0]['value'][1])
                if accepts + rejects > 0:
                    reject_rate = rejects / (accepts + rejects)
                    if reject_rate > 0.3:
                        ddos_score -= min(50, reject_rate * 100)
                        messages.append(f"High SYN cookie rejection rate: {reject_rate:.1%}")

            scores['ddos_protection'] = max(0, ddos_score)

            # If there's a critical failure and no working iRule, return zero score
            if critical_failure and not (irule_enabled and irule_active and irule_health > 80):
                return {
                    'total_score': 0,
                    'component_scores': scores,
                    'status': 'CRITICAL',
                    'details': {
                        'cpu_utilization': cpu_util if 'cpu_util' in locals() else None,
                        'current_connections': float(metrics.get('current_connections', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                        'connection_duration': float(metrics.get('connection_duration', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                        'irule_status': {
                            'enabled': irule_enabled,
                            'active': irule_active,
                            'health': irule_health
                        } if irule_enabled else None
                    },
                    'messages': messages,
                    'weights_used': weights,
                    'timestamp': datetime.now().isoformat()
                }

            # Calculate final score with adjusted weights
            total_score = sum(scores.get(metric, 0) * weight
                             for metric, weight in weights.items())

            # Determine status
            status = 'HEALTHY' if total_score >= 90 else 'WARNING' if total_score >= 70 else 'CRITICAL'

            return {
                'total_score': round(total_score, 2),
                'component_scores': scores,
                'status': status,
                'details': {
                    'cpu_utilization': cpu_util if 'cpu_util' in locals() else None,
                    'current_connections': float(metrics.get('current_connections', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                    'connection_duration': float(metrics.get('connection_duration', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                    'error_details': error_details,
                    'irule_status': {
                        'enabled': irule_enabled,
                        'active': irule_active,
                        'health': irule_health,
                        'executions': irule_executions if 'irule_executions' in locals() else 0,
                        'failures': irule_failures if 'irule_failures' in locals() else 0,
                        'aborts': irule_aborts if 'irule_aborts' in locals() else 0,
                        'failure_rate': failure_rate if 'failure_rate' in locals() else None
                    } if irule_enabled else None,
                    'traffic_metrics': {
                        'bytes_in': float(metrics.get('bytes_in', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                        'bytes_out': float(metrics.get('bytes_out', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                        'packets_in': float(metrics.get('packets_in', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                        'packets_out': float(metrics.get('packets_out', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1])
                    }
                },
                'messages': messages,
                'weights_used': weights,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error("Error calculating health score: %s", e)
            raise
            
    def store_health_score(self, vip_name: str, health_score: Dict[str, Any]):
        """Store health score, anomalies, and iRule metrics in ClickHouse"""
        try:
            if not health_score:
                logger.error("No health score data provided for VIP %s", vip_name)
                return

            current_time = datetime.now()

            # Delete any existing records for this VIP in the last 5 seconds
            self.clickhouse_client.execute("""
                ALTER TABLE vip_health.health_scores
                DELETE WHERE
                vip_name = %(vip_name)s
                AND timestamp >= toDateTime(%(time)s) - INTERVAL 5 SECOND
                AND timestamp <= toDateTime(%(time)s)
                """, {
                    'vip_name': vip_name,
                    'time': current_time.strftime('%Y-%m-%d %H:%M:%S')
                })

            # Insert the health score record with safe gets
            data = {
                'timestamp': current_time,
                'vip_name': vip_name,
                'total_score': health_score.get('total_score', 0),
                'availability_score': health_score.get('component_scores', {}).get('availability', 0),
                'performance_score': health_score.get('component_scores', {}).get('performance', 0),
                'pool_health_score': health_score.get('component_scores', {}).get('pool_health', 0),
                'response_health_score': health_score.get('component_scores', {}).get('response_health', 0),
                'ssl_health_score': health_score.get('component_scores', {}).get('ssl_health', 0),
                'connection_quality_score': health_score.get('component_scores', {}).get('connection_quality', 0),
                'ddos_protection_score': health_score.get('component_scores', {}).get('ddos_protection', 0),
                'status': health_score.get('status', 'UNKNOWN'),
                'cpu_utilization': float(health_score.get('details', {}).get('cpu_utilization', 0)),
                'current_connections': int(health_score.get('details', {}).get('current_connections', 0)),
                'connection_duration': float(health_score.get('details', {}).get('connection_duration', 0)),
                'messages': health_score.get('messages', [])
            }

            self.clickhouse_client.execute(
                'INSERT INTO vip_health.health_scores VALUES',
                [data]
            )

            # Store iRule metrics if present - with safe gets
            details = health_score.get('details', {})
            irule_status = details.get('irule_status', {})
            if irule_status:
                irule_data = {
                    'timestamp': current_time,
                    'vip_name': vip_name,
                    'irule_enabled': irule_status.get('enabled', False),
                    'irule_active': irule_status.get('active', False),
                    'irule_health': irule_status.get('health', 0),
                    'executions': irule_status.get('executions', 0),
                    'failures': irule_status.get('failures', 0),
                    'aborts': irule_status.get('aborts', 0),
                    'failure_rate': irule_status.get('failure_rate', 0.0) or 0.0
                }

                # Delete any existing iRule records
                self.clickhouse_client.execute("""
                    ALTER TABLE vip_health.irule_metrics
                    DELETE WHERE
                    vip_name = %(vip_name)s
                    AND timestamp >= toDateTime(%(time)s) - INTERVAL 5 SECOND
                    AND timestamp <= toDateTime(%(time)s)
                    """, {
                        'vip_name': vip_name,
                        'time': current_time.strftime('%Y-%m-%d %H:%M:%S')
                    })

                self.clickhouse_client.execute(
                    'INSERT INTO vip_health.irule_metrics VALUES',
                    [irule_data]
                )

            # Store anomalies if present
            if 'anomalies' in health_score:
                anomaly_records = []
                
                # Process day-over-day anomalies with safe gets
                for anomaly in health_score.get('anomalies', {}).get('day_over_day', []):
                    if not isinstance(anomaly, dict):
                        continue
                    anomaly_records.append({
                        'timestamp': current_time,
                        'vip_name': vip_name,
                        'metric': anomaly.get('metric', 'unknown'),
                        'current_value': float(anomaly.get('current_value', 0)),
                        'comparison_value': float(anomaly.get('comparison_value', 0)),
                        'deviation': float(anomaly.get('deviation', 0)),
                        'comparison_type': 'day_over_day'
                    })
                
                # Process seven-day anomalies with safe gets
                for anomaly in health_score.get('anomalies', {}).get('seven_day', []):
                    if not isinstance(anomaly, dict):
                        continue
                    anomaly_records.append({
                        'timestamp': current_time,
                        'vip_name': vip_name,
                        'metric': anomaly.get('metric', 'unknown'),
                        'current_value': float(anomaly.get('current_value', 0)),
                        'comparison_value': float(anomaly.get('comparison_value', 0)),
                        'deviation': float(anomaly.get('deviation', 0)),
                        'comparison_type': 'seven_day'
                    })

                if anomaly_records:
                    # Delete any existing anomaly records for this VIP in the last 5 seconds
                    self.clickhouse_client.execute("""
                        ALTER TABLE vip_health.anomalies
                        DELETE WHERE
                        vip_name = %(vip_name)s
                        AND timestamp >= toDateTime(%(time)s) - INTERVAL 5 SECOND
                        AND timestamp <= toDateTime(%(time)s)
                        """, {
                            'vip_name': vip_name,
                            'time': current_time.strftime('%Y-%m-%d %H:%M:%S')
                        })

                    # Insert the anomaly records
                    self.clickhouse_client.execute(
                        'INSERT INTO vip_health.anomalies VALUES',
                        anomaly_records
                    )

            logger.debug("Stored health score, iRule metrics, and anomalies for VIP %s", vip_name)
        except Exception as e:
            logger.error("Error storing health score for VIP %s: %s", vip_name, e)
            raise    
    def collect_all_vips(self):
        """Collect and store health scores for all VIPs"""
        try:
            vips = self.get_all_vips()
            logger.debug("Found %d VIPs to process" % len(vips))

            for vip_name in vips:
                try:
                    metrics = self.get_vip_metrics(vip_name)
                    historical_data = self.get_historical_metrics(vip_name)
                    anomalies = self.calculate_anomalies(metrics, historical_data)
                    health_score = self.calculate_health_score(metrics, vip_name)
                    
                    # Add anomalies to health score
                    health_score['anomalies'] = anomalies
                    
                    self.store_health_score(vip_name, health_score)
                except Exception as e:
                    logger.error("Error processing VIP %s: %s" % (vip_name, e))
                    continue

            logger.debug("Completed health score collection for all VIPs")
        except Exception as e:
            logger.error("Error in collection cycle: %s" % e)

    def get_all_vips(self) -> List[str]:
        """Get list of all VIPs from Prometheus"""
        try:
            query = 'f5_virtual_server_availability_ratio'
            url = "%s/api/v1/query?query=%s" % (self.prometheus_url, query)
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            vips = []
            if data.get('data', {}).get('result'):
                for result in data['data']['result']:
                    if 'f5_virtual_server_name' in result['metric']:
                        vips.append(result['metric']['f5_virtual_server_name'])
            return sorted(vips)
        except Exception as e:
            logger.error("Error getting VIP list: %s" % e)
            raise
    @app.route('/irules/<path:vip_name>')
    def get_irule_metrics(vip_name):
        """Get detailed iRule metrics for a VIP"""
        try:
            metrics = collector.get_vip_metrics(vip_name)
            
            irule_metrics = {
                'enabled': False,
                'metrics': {},
                'history': []
            }

            # Get current metrics
            irule_data = metrics.get('irule_enabled', {}).get('data', {}).get('result', [])
            if irule_data:
                for rule in irule_data:
                    if float(rule['value'][1]) == 1:
                        irule_metrics['enabled'] = True
                        executions = sum(float(metric['value'][1]) for metric in 
                            metrics.get('irule_executions', {}).get('data', {}).get('result', []))
                        failures = sum(float(metric['value'][1]) for metric in 
                            metrics.get('irule_failures', {}).get('data', {}).get('result', []))
                        aborts = sum(float(metric['value'][1]) for metric in 
                            metrics.get('irule_aborts', {}).get('data', {}).get('result', []))
                        
                        failure_rate = 0
                        if executions > 0:
                            failure_rate = (failures + aborts) / executions

                        irule_metrics['metrics'] = {
                            'executions': executions,
                            'failures': failures,
                            'aborts': aborts,
                            'failure_rate': failure_rate,
                            'health_impact': 'nominal' if failure_rate < 0.20 else 'degraded'
                        }
                        break

            # Get historical data
            try:
                history = collector.clickhouse_client.execute("""
                    SELECT 
                        timestamp,
                        executions,
                        failures,
                        aborts,
                        failure_rate
                    FROM vip_health.irule_metrics
                    WHERE vip_name = %(vip_name)s
                    AND timestamp >= now() - INTERVAL 1 DAY
                    ORDER BY timestamp DESC
                    LIMIT 100
                """, {'vip_name': vip_name})

                irule_metrics['history'] = [{
                    'timestamp': row[0].isoformat(),
                    'executions': row[1],
                    'failures': row[2],
                    'aborts': row[3],
                    'failure_rate': row[4]
                } for row in history]
            except Exception as e:
                logger.warning("Could not fetch iRule history: %s", e)

            return jsonify(irule_metrics)
        except Exception as e:
            logger.error("Error getting iRule metrics for VIP %s: %s", vip_name, e)
            return jsonify({'error': str(e)}), 500


@app.route('/debug')
def debug_info():
    """Get debug information about the collector"""
    try:
        query = 'f5_virtual_server_availability_ratio'
        url = "%s/api/v1/query?query=%s" % (collector.prometheus_url, query)
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        vips = []
        if data.get('data', {}).get('result'):
            for result in data['data']['result']:
                if 'f5_virtual_server_name' in result['metric']:
                    vips.append(result['metric']['f5_virtual_server_name'])

        return jsonify({
            'prometheus_url': collector.prometheus_url,
            'available_vips': sorted(vips) if vips else [],
            'metric_queries': {
                'availability': 'f5_virtual_server_availability_ratio',
                'enabled': 'f5_virtual_server_enabled_ratio',
                'cpu_utilization': 'f5_virtual_server_cpu_utilization_5s',
                'pool_health': 'f5_pool_availability_ratio',
                'member_health': 'f5_pool_member_availability_ratio',
                'http_responses': 'f5_virtual_server_profile_http_responses_by_status_total'
            }
        })
    except Exception as e:
        logger.error("Error in debug endpoint: %s" % e)
        return jsonify({'error': str(e)}), 500


@app.route('/health/<path:vip_name>')
def get_vip_health(vip_name):
    """Get health score for a specific VIP"""
    try:
        logger.info("Received request for VIP: %s" % vip_name)
        metrics = collector.get_vip_metrics(vip_name)
        historical_data = collector.get_historical_metrics(vip_name)
        anomalies = collector.calculate_anomalies(metrics, historical_data)
        health_score = collector.calculate_health_score(metrics, vip_name)
        health_score['anomalies'] = anomalies
        return jsonify(health_score)
    except Exception as e:
        logger.error("Error processing request for VIP %s: %s" % (vip_name, e))
        return jsonify({'error': str(e)}), 500


def main():
    global collector
    try:
        prometheus_url = os.environ.get('PROMETHEUS_URL', 'http://prometheus:9090')
        clickhouse_host = os.environ.get('CLICKHOUSE_HOST', 'clickhouse')
        collector = VIPHealthCollector(prometheus_url, clickhouse_host)
        app.run(host='0.0.0.0', port=8080)
    except Exception as e:
        logger.error("Error starting application: %s" % e)
        raise


if __name__ == '__main__':
    main()
