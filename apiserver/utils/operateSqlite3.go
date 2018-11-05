package utils

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3" //sqlite3 dirver
)

type appContext struct {
	db *sql.DB
}

type BlackListCnt struct {
	Id      int
	Type    string
	ListCnt uint64
}
type AddressToPk struct {
	Address string
	Key     string
}

/* ##############################################
* description: 连接数据库
* input:       driverName	用的驱动名称
*			   dbName		数据库名称
* output:      返回数据库内容
* ###############################################*/
func ConnectDB(driverName string, dbName string) (*appContext, error) {
	db, err := sql.Open(driverName, dbName)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &appContext{db}, nil
}

/* ##############################################
* description: 断开与数据库的链接
* input:       无
* output:      error信息
* ###############################################*/
func (c *appContext) DisConnectDB() error {
	err := c.db.Close()
	if err != nil {
		return err
	}
	return nil
}

/* ##############################################
* description: 创建数据表
* input:       无
* output:      error信息
* ###############################################*/
func (c *appContext) CreateTable() error {
	sqlStmt := `
	create table BlackListCnt(Id integer not null primary key, Type text, ListCnt integer);
	`
	// delete from foo;
	_, err := c.db.Exec(sqlStmt)
	if err != nil {
		Log.Errorf("Sqlite3 create table err: %q: %s\n", err, sqlStmt)
		return err
	}

	sqlStmt = `
	create table AddressToPk(address text not null primary key, privatekey text not null);
	`
	_, err = c.db.Exec(sqlStmt)
	if err != nil {
		Log.Errorf("Sqlite3 create table err: %q: %s\n", err, sqlStmt)
		return err
	}
	return nil
}

/* ##############################################
* description: 插入数据
* input:       Type：	黑名单类型（"TotalCnt"、"1~7"、"2018-3"）
*			   ListCnt：黑名单数量
* output:      error信息
* ###############################################*/
func (c *appContext) InsertTable(blacklistCntList []BlackListCnt) error {
	tx, err := c.db.Begin()
	if err != nil {
		Log.Errorf("Sqlite3 insert table begin error , %s", err.Error())
		return err
	}
	stmt, err := c.db.Prepare("insert into BlackListCnt(Type, ListCnt) values(?,?)")
	if err != nil {
		Log.Errorf("Sqlite3 insert table prepare error , %s", err.Error())
		return err
	}
	defer stmt.Close()
	for _, blacklistCnt := range blacklistCntList {
		_, err = stmt.Exec(blacklistCnt.Type, blacklistCnt.ListCnt)
		if err != nil {
			Log.Errorf("Sqlite3 insert table error , %s", err.Error())
			return err
		}
	}
	tx.Commit()
	return nil
}
func (c *appContext) InsertAddressTable(atp AddressToPk) error {
	tx, err := c.db.Begin()
	if err != nil {
		Log.Errorf("Sqlite3 insert table begin error , %s", err.Error())
		return err
	}

	stmt, err := c.db.Prepare("insert into AddressToPk(address, privatekey) values(?,?)")
	if err != nil {
		Log.Errorf("Sqlite3 insert table prepare error , %s", err.Error())
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(atp.Address, atp.Key)
	if err != nil {
		Log.Errorf("Sqlite3 insert table error , %s", err.Error())
		return err
	}

	tx.Commit()
	return nil
}
func (c *appContext) QueryAddressTable(ad string) (string, error) {

	stmt, err := c.db.Prepare("select * from AddressToPk where address = ?")
	if err != nil {
		Log.Errorf("Sqlite3 query table prepare error , %s", err.Error())
		return "", err
	}
	defer stmt.Close()
	//blacklistCntList := []BlackListCnt{}
	atp := new(AddressToPk)
	err = stmt.QueryRow(ad).Scan(&atp.Address, &atp.Key)

	if err != nil {
		Log.Errorf("Sqlite3 query table rows error , %s", err.Error())
		return "", err
	}
	return atp.Key, nil
}

/* ##############################################
* description: 读取数据表
* input:       无
* output:      Type：	黑名单类型（"TotalCnt"、"1~7"、"2018-3"）
*			   ListCnt：黑名单数量
*			   error信息
* ###############################################*/
func (c *appContext) QueryTable() ([]BlackListCnt, error) {
	rows, err := c.db.Query("select * from BlackListCnt")
	if err != nil {
		Log.Errorf("Sqlite3 query table error , %s", err.Error())
		return nil, err
	}
	defer rows.Close()
	blacklistCntList := []BlackListCnt{}
	for rows.Next() {
		blackListCnt := new(BlackListCnt)
		err = rows.Scan(&blackListCnt.Id, &blackListCnt.Type, &blackListCnt.ListCnt)
		if err != nil {
			Log.Errorf("Sqlite3 query table Scan error , %s", err.Error())
			return nil, err
		}
		blacklistCntList = append(blacklistCntList, *blackListCnt)
	}
	err = rows.Err()
	if err != nil {
		Log.Errorf("Sqlite3 query table rows error , %s", err.Error())
	}
	return blacklistCntList, nil
}

/* ##############################################
* description: 跟新数据表
* input:       Type：	黑名单类型（"TotalCnt"、"1~7"、"2018-3"）
*			   ListCnt：黑名单数量
* output:      error信息
* ###############################################*/
func (c *appContext) UpdateTable(blacklistCntList []BlackListCnt) error {
	stmt, err := c.db.Prepare("update BlackListCnt set ListCnt = ? WHERE Type = ?")
	if err != nil {
		Log.Errorf("Sqlite3 update table prepare error , %s", err.Error())
		return err
	}
	defer stmt.Close()
	for _, blacklistCnt := range blacklistCntList {
		_, err := stmt.Exec(blacklistCnt.ListCnt, blacklistCnt.Type)
		if err != nil {
			Log.Errorf("Sqlite3 update table exec error , %s", err.Error())
			return err
		}
	}
	return nil
}

/* ##############################################
* description: 删除数据表
* input:       Type：	黑名单类型（"TotalCnt"、"1~7"、"2018-3"）
*			   ListCnt：黑名单数量
* output:      error信息
* ###############################################*/
func (c *appContext) DeleteTable(blacklistCntList []BlackListCnt) error {
	stmt, err := c.db.Prepare("delete from BlackListCnt where Type = ?")
	if err != nil {
		Log.Errorf("Sqlite3 delete table prepare error , %s", err.Error())
		return err
	}
	defer stmt.Close()
	for _, blacklistCnt := range blacklistCntList {
		_, err := stmt.Exec(blacklistCnt.Type)
		if err != nil {
			Log.Errorf("Sqlite3 delete table exec error , %s", err.Error())
			return err
		}
	}
	return nil
}

/* ##############################################
* description: 判断文件或文件夹是否存在
* input:       文件或文件夹
* output:      没有error时，true表示文件存在，false
*			   表示文件不存在。
* ###############################################*/
func FileOrDirectoryExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil //文件或文件夹存在
	}
	if os.IsNotExist(err) {
		return false, nil //文件或文件夹不存在
	}
	return true, err //其他错误
}
