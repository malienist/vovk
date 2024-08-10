import requests
import sys
import time

API_KEY = 'insert_your_api_key'
VT_URL = 'https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs'

def create_retro_hunt(yara_filename):
    with open(yara_filename, 'r') as file:
        yara_rule = file.read()

    headers = {
        'x-apikey': API_KEY,
        'Content-Type': 'application/json'
    }

    data = {
        "data": {
            "type": "retrohunt_job",
            "attributes": {
                "rules": yara_rule
            }
        }
    }

    response = requests.post(VT_URL, headers=headers, json=data)

    if response.status_code == 200:
        print("Retro Hunt job created successfully!")
        job_id = response.json()['data']['id']
        print(f"Job ID: {job_id}")
        return job_id
    else:
        print(f"Error creating Retro Hunt job: {response.status_code}")
        print(response.text)
        sys.exit(1)

def get_retro_hunt_results(job_id):
    headers = {
        'x-apikey': API_KEY
    }

    job_url = f'{VT_URL}/{job_id}'

    while True:
        response = requests.get(job_url, headers=headers)
        if response.status_code == 200:
            job_status = response.json()['data']['attributes']['status']
            if job_status == 'completed':
                print("Retro Hunt job completed!")
                return response.json()['data']['attributes']['ruleset_matches']
            else:
                print(f"Retro Hunt job status: {job_status}. Checking again in 60 seconds...")
                time.sleep(60)
        else:
            print(f"Error checking Retro Hunt job status: {response.status_code}")
            print(response.text)
            sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python retro_hunt.py yara_filename")
        sys.exit(1)

    yara_filename = sys.argv[1]

    job_id = create_retro_hunt(yara_filename)
    results = get_retro_hunt_results(job_id)

    if results:
        print("Retro Hunt results:")
        for result in results:
            print(result)
    else:
        print("No matches found.")

