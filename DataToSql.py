import pymysql.cursors
from pymysql.converters import escape_string

class DataToMysql:
    def __init__(self, user, passwd, db):
        try:
            # Connect to the database.
            self.connection = pymysql.connect(host = 'localhost',
                                              user = user,
                                              password = passwd,
                                              database = db,
                                              port = 3306,
                                              charset = 'utf8',
                                              cursorclass = pymysql.cursors.DictCursor)
            self.cursor = self.connection.cursor()
            self.db = db
        except pymysql.Error as e:
            print("Connection failed!")
            raise e

    def table_exists(self, table_name):
        '''
            Return: bool
        '''
        sql = "show tables;"
        self.cursor.execute(sql)
        tables = self.cursor.fetchall()
        for _t in tables:
            if table_name in _t.values():
                return True
        return False

    def create_table(self, data: dict, table_name):
        sql_key_str = ""
        columnStyle = ' text'  # 数据库字段类型
        for key in data.keys():
            sql_key_str = sql_key_str + ' ' + '`' + str(key) + '`' + columnStyle + ','
        print(sql_key_str)
        temp = "CREATE TABLE %s (%s)" % (table_name, sql_key_str[:-1])
        print(temp)
        self.cursor.execute("CREATE TABLE %s (%s)" % (table_name, sql_key_str[:-1]))
        # 添加自增ID
        self.cursor.execute("""ALTER TABLE `{}` \
                    ADD COLUMN `id` INT NOT NULL AUTO_INCREMENT FIRST, \
                    ADD PRIMARY KEY (`id`);"""
                            .format(table_name))
        # 添加创建时间
        self.cursor.execute(
            """ALTER TABLE {} ADD join_time timestamp NULL DEFAULT current_timestamp();""".format(table_name))

    def write_dict(self, data: dict, table_name):
        """
        写入mysql，如果没有表，创建表
        :param data: 字典类型
        :param table_name: 表名
        :return:
        """
        if not self.table_exists(table_name):
            self.create_table(data, table_name)
        sql_key = ''  # 数据库行字段
        sql_value = ''  # 数据库值
        for key in data.keys():  # 生成insert插入语句
            # escape_string用来转义字符串
            sql_value = (sql_value + '"' + escape_string(str(data[key])) + '"' + ',')
            sql_key = sql_key + ' ' + '`' + key + '`' + ','

        self.cursor.execute(
            "INSERT INTO %s (%s) VALUES (%s)" % (table_name, sql_key[:-1], sql_value[:-1]))
        self.connection.commit()  # 提交当前事务


if __name__ == '__main__':
    mysql = DataToMysql('root', 'ujG0yrpK3Z&0', 'fsm')
    test_data = {"col1": 1, "col2": "a", "col3": 1.5}
    mysql.write_dict(test_data, table_name="test_table")
    test_data_2 = {"col1": 2, "col2": "b", "col3": 1.6}
    mysql.write_dict(test_data_2, table_name="test_table")