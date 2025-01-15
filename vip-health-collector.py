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
            
    def get_vip_metrics(self, vip_name: str) -> Dict[str, Any]:
        """Collect all relevant metrics for a VIP"""
        try:
            # Ensure VIP name starts with /
            if not vip_name.startswith('/'):
                vip_name = '/' + vip_name

            # Get pool name first
            pool_name = self.get_pool_name(vip_name)
            if not pool_name:
                raise ValueError("No pool found for VIP %s" % vip_name)

            logger.debug("Using pool %s for VIP %s" % (pool_name, vip_name))

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

                # Pool health metrics
                'pool_availability': 'f5_pool_availability_ratio%7Bf5_pool_name%3D%22' + pool_name + '%22,availability_state%3D%22available%22%7D',
                'pool_member_availability': 'f5_pool_member_availability_ratio%7Bf5_pool_name%3D%22' + pool_name + '%22,availability_state%3D%22available%22%7D',
                'pool_member_count': 'f5_pool_member_count%7Bf5_pool_name%3D%22' + pool_name + '%22,active_state%3D%22active%22%7D',

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

            for metric_name, query in metric_queries.items():
                url = "%s/api/v1/query?query=%s" % (self.prometheus_url, query)
                response = requests.get(url)
                response.raise_for_status()
                metrics[metric_name] = response.json()

            return metrics

        except Exception as e:
            logger.error("Error collecting metrics for VIP %s: %s" % (vip_name, e))
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
        """Calculate anomalies by comparing current metrics with historical data"""
        try:
            today = datetime.now().strftime('%Y-%m-%d')
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            
            # Get the last 7 days of data (excluding today)
            seven_day_data = {}
            for date, metrics in historical_data.items():
                if date != today:
                    for metric, value in metrics.items():
                        if metric not in seven_day_data:
                            seven_day_data[metric] = []
                        seven_day_data[metric].append(value)

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

            metrics_to_check = [
                'total_score', 'availability_score', 'performance_score',
                'pool_health_score', 'response_health_score', 'ssl_health_score',
                'connection_quality_score', 'ddos_protection_score', 'cpu_utilization',
                'current_connections', 'connection_duration'
            ]

            for metric in metrics_to_check:
                current_value = current_metrics.get(metric, 0)
                metric_anomalies = {
                    'current_value': current_value,
                    'day_over_day': None,
                    'seven_day': None
                }

                # Day-over-day comparison
                if yesterday in historical_data:
                    yesterday_value = historical_data[yesterday].get(metric, 0)
                    if yesterday_value != 0:  # Avoid division by zero
                        day_deviation = abs((current_value - yesterday_value) / yesterday_value * 100)
                        metric_anomalies['day_over_day'] = {
                            'value': yesterday_value,
                            'deviation': round(day_deviation, 2)
                        }
                        if day_deviation > 20:
                            anomalies['day_over_day'].append({
                                'metric': metric,
                                'current_value': current_value,
                                'comparison_value': yesterday_value,
                                'deviation': round(day_deviation, 2)
                            })

                # Seven-day comparison
                if metric in seven_day_averages:
                    avg_value = seven_day_averages[metric]
                    if avg_value != 0:  # Avoid division by zero
                        week_deviation = abs((current_value - avg_value) / avg_value * 100)
                        metric_anomalies['seven_day'] = {
                            'value': avg_value,
                            'deviation': round(week_deviation, 2)
                        }
                        if week_deviation > 20:
                            anomalies['seven_day'].append({
                                'metric': metric,
                                'current_value': current_value,
                                'comparison_value': avg_value,
                                'deviation': round(week_deviation, 2)
                            })

                anomalies['metrics'][metric] = metric_anomalies

            return anomalies

        except Exception as e:
            logger.error("Error calculating anomalies: %s" % e)
            raise

    def calculate_health_score(self, metrics: Dict[str, Any], vip_name: str = None) -> Dict[str, Any]:
        """Calculate comprehensive health score"""
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
            # Critical availability checks - these will force total_score to 0 if they fail
            critical_failure = False
            
            # VIP Availability Check
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
                                critical_failure = True
                                messages.append("VIP is not available")
                        break

            # Pool Health Critical Check
            pool_data = metrics.get('pool_availability', {}).get('data', {}).get('result', [])
            if pool_data:
                pool_availability = float(pool_data[0]['value'][1])
                if pool_availability == 0:
                    critical_failure = True
                    messages.append("Pool is not available")
                
            pool_member_data = metrics.get('pool_member_availability', {}).get('data', {}).get('result', [])
            if pool_member_data:
                available_members = sum(1 for member in pool_member_data
                                     if float(member['value'][1]) == 1)
                if available_members == 0:
                    critical_failure = True
                    messages.append("No pool members are available")

            # If there's a critical failure, return immediately with a zero score
            if critical_failure:
                return {
                    'total_score': 0,
                    'component_scores': scores,
                    'status': 'CRITICAL',
                    'details': {
                        'cpu_utilization': float(metrics.get('cpu_utilization', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                        'current_connections': float(metrics.get('current_connections', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                        'connection_duration': float(metrics.get('connection_duration', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                    },
                    'messages': messages,
                    'weights_used': weights,
                    'timestamp': datetime.now().isoformat()
                }

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

            # Pool Health Score (20% of total)
            pool_score = 100
            if pool_data:
                pool_score *= float(pool_data[0]['value'][1])

            if pool_member_data:
                available_members = sum(1 for member in pool_member_data
                                     if float(member['value'][1]) == 1)
                total_members = len(pool_member_data)
                if total_members > 0:
                    pool_score *= (available_members / total_members)
                    if available_members < total_members:
                        messages.append(f"Only {available_members} of {total_members} pool members available")

            scores['pool_health'] = pool_score

            # Response Code Health Score (15% of total)
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

            # Check 4xx errors
            http_4xx = metrics.get('http_4xx_responses', {}).get('data', {}).get('result', [])
            if http_4xx:
                error_4xx_count = float(http_4xx[0]['value'][1])
                if error_4xx_count > 10:
                    penalty = min(30, (error_4xx_count - 10) * 2)
                    http_score -= penalty
                    error_details['4xx_errors'] = {
                        'count': error_4xx_count,
                        'penalty': penalty
                    }
                    messages.append(f"High number of 4xx errors: {error_4xx_count} (-{penalty} points)")

            scores['response_health'] = max(0, http_score)

            # SSL Health Score (10% of total)
            ssl_score = 100
            ssl_handshake_failures = metrics.get('ssl_handshake_failures', {}).get('data', {}).get('result', [])
            ssl_secure_handshakes = metrics.get('ssl_secure_handshakes', {}).get('data', {}).get('result', [])

            if ssl_handshake_failures and ssl_secure_handshakes:
                failures = float(ssl_handshake_failures[0]['value'][1])
                successes = float(ssl_secure_handshakes[0]['value'][1])
                if failures + successes > 0:
                    failure_rate = failures / (failures + successes)
                    if failure_rate > 0.1:  # More than 10% failure rate
                        ssl_score -= min(50, failure_rate * 100)
                        messages.append(f"High SSL handshake failure rate: {failure_rate:.1%}")

            scores['ssl_health'] = max(0, ssl_score)

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

            if conn_slow_killed:
                slow_killed = float(conn_slow_killed[0]['value'][1])
                if slow_killed > 0:
                    penalty = min(40, slow_killed * 5)
                    conn_score -= penalty
                    messages.append(f"Slow connections killed: {slow_killed} (-{penalty} points)")

            scores['connection_quality'] = max(0, conn_score)

            # DDoS Protection Score (10% of total)
            ddos_score = 100
            syncookie_accepts = metrics.get('syncookie_accepts', {}).get('data', {}).get('result', [])
            syncookie_rejects = metrics.get('syncookie_rejects', {}).get('data', {}).get('result', [])

            if syncookie_accepts and syncookie_rejects:
                accepts = float(syncookie_accepts[0]['value'][1])
                rejects = float(syncookie_rejects[0]['value'][1])
                if accepts + rejects > 0:
                    reject_rate = rejects / (accepts + rejects)
                    if reject_rate > 0.3:  # More than 30% rejection rate
                        ddos_score -= min(50, reject_rate * 100)
                        messages.append(f"High SYN cookie rejection rate: {reject_rate:.1%}")

            scores['ddos_protection'] = max(0, ddos_score)
    # Normalize weights if any component was removed
            if weights:
                weight_sum = sum(weights.values())
                weights = {k: v/weight_sum for k, v in weights.items()}

            # Calculate weighted total
            total_score = sum(scores.get(metric, 0) * weight
                            for metric, weight in weights.items())

            status = 'HEALTHY' if total_score >= 90 else 'WARNING' if total_score >= 70 else 'CRITICAL'

            # Prepare current metrics for anomaly detection
            current_metrics = {
                'total_score': total_score,
                'availability_score': scores.get('availability', 0),
                'performance_score': scores.get('performance', 0),
                'pool_health_score': scores.get('pool_health', 0),
                'response_health_score': scores.get('response_health', 0),
                'ssl_health_score': scores.get('ssl_health', 0),
                'connection_quality_score': scores.get('connection_quality', 0),
                'ddos_protection_score': scores.get('ddos_protection', 0),
                'cpu_utilization': cpu_util if 'cpu_util' in locals() else 0,
                'current_connections': float(metrics.get('current_connections', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1]),
                'connection_duration': float(metrics.get('connection_duration', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1])
            }

            # Get historical data and calculate anomalies if VIP name is provided
            anomalies = None
            if vip_name:
                try:
                    historical_data = self.get_historical_metrics(vip_name)
                    if historical_data:
                        anomalies = self.calculate_anomalies(current_metrics, historical_data)
                        
                        # Add anomaly messages if any found
                        if anomalies:
                            for anomaly in anomalies.get('day_over_day', []):
                                messages.append(f"Day-over-day anomaly detected in {anomaly['metric']}: "
                                             f"Current: {anomaly['current_value']:.2f}, "
                                             f"Yesterday: {anomaly['comparison_value']:.2f}, "
                                             f"Deviation: {anomaly['deviation']:.2f}%")
                            
                            for anomaly in anomalies.get('seven_day', []):
                                messages.append(f"Seven-day anomaly detected in {anomaly['metric']}: "
                                             f"Current: {anomaly['current_value']:.2f}, "
                                             f"7-day avg: {anomaly['comparison_value']:.2f}, "
                                             f"Deviation: {anomaly['deviation']:.2f}%")
                except Exception as e:
                    logger.error(f"Error in anomaly detection for VIP {vip_name}: {e}")
                    messages.append(f"Anomaly detection failed: {str(e)}")

            return {
                'total_score': round(total_score, 2),
                'component_scores': scores,
                'status': status,
                'details': {
                    'cpu_utilization': cpu_util if 'cpu_util' in locals() else None,
                    'current_connections': metrics.get('current_connections', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1],
                    'connection_duration': metrics.get('connection_duration', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1],
                    'error_details': error_details if 'error_details' in locals() else {}
                },
                'anomalies': anomalies,
                'messages': messages,
                'weights_used': weights,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error("Error calculating health score: %s" % e)
            raise

    def store_health_score(self, vip_name: str, health_score: Dict[str, Any]):
        """Store health score and anomalies in ClickHouse"""
        try:
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

            # Insert the health score record
            data = {
                'timestamp': current_time,
                'vip_name': vip_name,
                'total_score': health_score['total_score'],
                'availability_score': health_score['component_scores'].get('availability', 0),
                'performance_score': health_score['component_scores'].get('performance', 0),
                'pool_health_score': health_score['component_scores'].get('pool_health', 0),
                'response_health_score': health_score['component_scores'].get('response_health', 0),
                'ssl_health_score': health_score['component_scores'].get('ssl_health', 0),
                'connection_quality_score': health_score['component_scores'].get('connection_quality', 0),
                'ddos_protection_score': health_score['component_scores'].get('ddos_protection', 0),
                'status': health_score['status'],
                'cpu_utilization': float(health_score['details'].get('cpu_utilization', 0)) if health_score['details'].get('cpu_utilization') is not None else 0.0,
                'current_connections': int(health_score['details'].get('current_connections', 0)),
                'connection_duration': float(health_score['details'].get('connection_duration', 0)),
                'messages': health_score.get('messages', [])
            }

            self.clickhouse_client.execute(
                'INSERT INTO vip_health.health_scores VALUES',
                [data]
            )

            # Store anomalies if present
            if 'anomalies' in health_score:
                anomaly_records = []
                
                # Process day-over-day anomalies
                for anomaly in health_score['anomalies'].get('day_over_day', []):
                    anomaly_records.append({
                        'timestamp': current_time,
                        'vip_name': vip_name,
                        'metric': anomaly['metric'],
                        'current_value': float(anomaly['current_value']),
                        'comparison_value': float(anomaly['comparison_value']),
                        'deviation': float(anomaly['deviation']),
                        'comparison_type': 'day_over_day'
                    })
                
                # Process seven-day anomalies
                for anomaly in health_score['anomalies'].get('seven_day', []):
                    anomaly_records.append({
                        'timestamp': current_time,
                        'vip_name': vip_name,
                        'metric': anomaly['metric'],
                        'current_value': float(anomaly['current_value']),
                        'comparison_value': float(anomaly['comparison_value']),
                        'deviation': float(anomaly['deviation']),
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

            logger.debug("Stored health score and anomalies for VIP %s" % vip_name)
        except Exception as e:
            logger.error("Error storing health score for VIP %s: %s" % (vip_name, e))
            raise

    def collect_all_vips(self):
        """Collect and store health scores for all VIPs"""
        try:
            vips = self.get_all_vips()
            logger.debug("Found %d VIPs to process" % len(vips))

            for vip_name in vips:
                try:
                    metrics = self.get_vip_metrics(vip_name)
                    health_score = self.calculate_health_score(metrics, vip_name)  # Pass vip_name for anomaly detection
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
        health_score = collector.calculate_health_score(metrics, vip_name)  # Pass vip_name for anomaly detection
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
