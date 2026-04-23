import time
import random
import json
from datetime import datetime

def generate_realtime_data():
    """
    Generator function that yields real-time mock data for AWS resources.
    Simulates data for EC2 instances: CPU usage, memory usage, network in/out, etc.
    """
    instance_ids = ['i-1234567890abcdef0', 'i-0987654321fedcba0', 'i-abcdef1234567890']

    while True:
        timestamp = datetime.utcnow().isoformat() + 'Z'
        for instance_id in instance_ids:
            data = {
                'timestamp': timestamp,
                'instance_id': instance_id,
                'cpu_utilization': round(random.uniform(0, 100), 2),
                'memory_utilization': round(random.uniform(0, 100), 2),
                'network_in': random.randint(1000, 100000),
                'network_out': random.randint(1000, 100000),
                'disk_read_ops': random.randint(0, 1000),
                'disk_write_ops': random.randint(0, 1000),
                'status': random.choice(['running', 'stopped', 'terminated'])
            }
            yield data
        time.sleep(1)  # Generate data every secondx

if __name__ == "__main__":
    print("Starting real-time data generator...")
    print("Press Ctrl+C to stop.")
    try:
        for data_point in generate_realtime_data():
            print(json.dumps(data_point, indent=2))
    except KeyboardInterrupt:
        print("\nStopped.")