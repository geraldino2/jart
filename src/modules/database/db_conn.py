import pymysql

class DB_Connection:
    def __init__(
            self, 
            db_host, 
            db_user, 
            db_password
        ) -> None:
        """
        Initialize class.

        :param db_host: the DB host (usually, `localhost`)
        :param db_user: the DB username
        :param db_password: the DB password
        """
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        return


    def connect(self) -> pymysql.connections.Connection:
        """
        Try connecting to the database using credentials passed in init.

        :returns: the DB connection, as pymysql.connections.Connection
        """
        return(pymysql.connect(
            host = self.db_host,
            user = self.db_user,
            password = self.db_password
        ))
