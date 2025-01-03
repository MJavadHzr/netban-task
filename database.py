import psycopg2


class DataBase:
    def __init__(self, db_name, user, password, host='localhost', db_port=5432):
        self.db_params = {
            'dbname': db_name,
            'user': user,
            'password': password,
            'host': host,
            'port': db_port
        }
        self._connect()

    def _connect(self):
        self.conn = psycopg2.connect(**self.db_params)
        self.cursor = self.conn.cursor()

    def disconnect(self):
        if self.conn:
            self.cursor.close()
            self.conn.close()

    def query(self, sql):
        self.cursor.execute(sql)
        self.conn.commit()
        return self.cursor.fetchall()