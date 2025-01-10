import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from flask import Flask, jsonify
import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vip-health-collector')

class VIPHealthCollector:
    def __init__(self, prometheus_url: str):
        self.prometheus_url = prometheus_url
        logger.info("Initialized collector with Prometheus URL: %s" % prometheus_url)

    def get_pool_name(self, vip_name: str) -> Optional[str]:
        """Get pool name from VIP info"""
        try:
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
                return data['data']['result'][0]['metric'].get('f5_pool_name')
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

            logger.info("Found pool %s for VIP %s" % (pool_name, vip_name))

            metrics = {}
            metric_queries = {
                'availability': 'f5_virtual_server_availability_ratio%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'enabled': 'f5_virtual_server_enabled_ratio%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'cpu_utilization': 'f5_virtual_server_cpu_utilization_5s%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',

                # Performance Metrics
                'current_connections': 'f5_virtual_server_clientside_connection_count%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',
                'connection_duration': 'f5_virtual_server_clientside_connection_duration_mean_milliseconds%7Bf5_virtual_server_name%3D%22' + vip_name + '%22%7D',

                # Pool Metrics using pool name
                'pool_availability': 'f5_pool_availability_ratio%7Bf5_pool_name%3D%22' + pool_name + '%22,availability_state%3D%22available%22%7D',
                'pool_member_availability': 'f5_pool_member_availability_ratio%7Bf5_pool_name%3D%22' + pool_name + '%22,availability_state%3D%22available%22%7D',
                'pool_member_count': 'f5_pool_member_count%7Bf5_pool_name%3D%22' + pool_name + '%22,active_state%3D%22active%22%7D'
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

    def calculate_health_score(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive health score"""
        scores = {}
        messages = []
        weights = {
            'availability': 0.30,
            'performance': 0.25,
            'pool_health': 0.45
        }

        try:
            # VIP Availability Score (30% of total by default)
            avail_data = metrics.get('availability', {}).get('data', {}).get('result', [])
            if avail_data:
                # Check each state (available, offline, unknown)
                for state in avail_data:
                    # Get the availability state and its value
                    availability_state = state['metric'].get('availability_state')
                    value = float(state['value'][1])
                    # If this state has value 1, it's the current state
                    if value == 1:
                        scores['availability_state'] = availability_state
                        if availability_state == 'unknown':
                            # Remove availability from weights and add message
                            weights.pop('availability')
                            messages.append("An appropriate health monitor is necessary to determine availability health - the weighted score for availability has been removed")
                        else:
                            scores['availability'] = 100 if availability_state == 'available' else 0
                        break

            enabled_data = metrics.get('enabled', {}).get('data', {}).get('result', [])
            if enabled_data:
                scores['enabled'] = 100 if float(enabled_data[0]['value'][1]) == 1 else 0

            # Performance Score (25% of total)
            perf_score = 100
            cpu_data = metrics.get('cpu_utilization', {}).get('data', {}).get('result', [])
            if cpu_data:
                cpu_util = float(cpu_data[0]['value'][1])
                if cpu_util > 90:
                    perf_score -= 30
                elif cpu_util > 75:
                    perf_score -= 15

            scores['performance'] = max(0, perf_score)

            # Pool Health Score (45% of total)
            pool_score = 100
            pool_data = metrics.get('pool_availability', {}).get('data', {}).get('result', [])
            if pool_data:
                pool_score *= float(pool_data[0]['value'][1])

            pool_member_data = metrics.get('pool_member_availability', {}).get('data', {}).get('result', [])
            if pool_member_data:
                available_members = sum(1 for member in pool_member_data
                                     if float(member['value'][1]) == 1)
                total_members = len(pool_member_data)
                if total_members > 0:
                    pool_score *= (available_members / total_members)

            scores['pool_health'] = pool_score

            # Normalize weights if availability was removed
            if weights:
                weight_sum = sum(weights.values())
                weights = {k: v/weight_sum for k, v in weights.items()}

            # Calculate weighted total based on available weights
            total_score = sum(scores.get(metric, 0) * weight
                            for metric, weight in weights.items())

            status = 'HEALTHY' if total_score >= 90 else 'WARNING' if total_score >= 70 else 'CRITICAL'

            return {
                'total_score': round(total_score, 2),
                'component_scores': scores,
                'status': status,
                'details': {
                    'cpu_utilization': cpu_util if 'cpu_util' in locals() else None,
                    'current_connections': metrics.get('current_connections', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1],
                    'connection_duration': metrics.get('connection_duration', {}).get('data', {}).get('result', [{}])[0].get('value', [0, 0])[-1],
                },
                'messages': messages,
                'weights_used': weights,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error("Error calculating health score: %s" % e)
            raise

app = Flask(__name__)
collector = None

@app.route('/debug')
def debug_info():
    """Get debug information about the collector"""
    try:
        # Build query using exact working format
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
                'member_health': 'f5_pool_member_availability_ratio'
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
        health_score = collector.calculate_health_score(metrics)
        return jsonify(health_score)
    except Exception as e:
        logger.error("Error processing request for VIP %s: %s" % (vip_name, e))
        return jsonify({'error': str(e)}), 500

def main():
    global collector
    try:
        prometheus_url = os.environ.get('PROMETHEUS_URL', 'http://prometheus:9090')
        collector = VIPHealthCollector(prometheus_url)
        app.run(host='0.0.0.0', port=8080)
    except Exception as e:
        logger.error("Error starting application: %s" % e)
        raise

if __name__ == '__main__':
    main()
