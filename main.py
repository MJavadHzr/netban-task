import argparse
from flask import Flask
from database import DataBase
from sim_finder import SimFinder

app = Flask(__name__)

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=8080)
parser.add_argument('--db-name', type=str, required=True)
parser.add_argument('--user', type=str, required=True)
parser.add_argument('--password', type=str, required=True)
parser.add_argument('--model', type=str, default='all-MiniLM-L6-v2')
parser.add_argument('--threshold', type=float, default=0.5)
args = parser.parse_args()


@app.route("/vulnerabilities", methods=['GET'])
def vulnerabilities():
    result = sim_founder.get_sims()
    return result


if __name__ == '__main__':
    db = DataBase(
        args.db_name,
        args.user,
        args.password
    )
    sim_founder = SimFounder(db, args.model, args.threshold)

    app.run(port=args.port, debug=False)
