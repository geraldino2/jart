import pymysql

class DB_Connection:
    def __init__(self,db_host,db_user,db_password):
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password

    def connect(self):
        return(pymysql.connect(
            host = self.db_host,
            user = self.db_user,
            password = self.db_password
        ))
