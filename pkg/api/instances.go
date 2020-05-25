package api

import (
	"fmt"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/search"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"math/rand"
	"os"
	"time"
)

func QueryInstances(instance string) (int64, int64, error) {
	logger.Info("Query Instance", "id", instance)
	userQuery := models.GetUserByLoginQuery{LoginOrEmail: instance}

	if err := bus.Dispatch(&userQuery); err != nil {
		logger.Info("Query User "+instance+" Failed ", "err", err.Error())
		return 0, 0, err
	}

	orgQuery := models.GetOrgByNameQuery{
		Name: instance,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+instance+" Failed: ", "err", err.Error())
		return 0, 0, err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + instance + " Not Found !")
		return 0, 0, fmt.Errorf("Query Org " + instance + " Not Found !")
	}

	user := userQuery.Result

	logger.Info("Query Instance Success!")
	return user.Id, userQuery.Result.OrgId, nil
}

// POST /instances/:instance  (create instances in grafana for nebula)
func CreateInstances(c *models.ReqContext) Response {
	instance := c.Params(":instanceID")
	logger.Info("Create Instance", "id", instance)
	err := createOrg(instance)
	if err != nil {
		return Error(500, "Failed to Create Org", err)
	}

	logger.Info("Create Org Success")

	err = createUser(instance)
	if err != nil {
		return Error(500, "Failed to Create User", err)
	}
	logger.Info("Create User Success")

	err = createDashboard(instance, instance)
	if err != nil {
		return Error(500, "Failed to Create Dashboard", err)
	}

	logger.Info("Create Dashboard Success")

	err = createDataSource(instance)

	if err != nil {
		return Error(500, "Failed to Create DataSources", err)
	}

	logger.Info("Create DataSource Success")

	return JSON(200, map[string]string{})
}

func createUser(instance string) error {
	orgQuery := models.GetOrgByNameQuery{
		Name: instance,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+instance+" Failed: ", "err", err.Error())
		return err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + instance + " Not Found !")
		return fmt.Errorf("Query Org " + instance + " Not Found !")
	}

	cmd := models.CreateUserCommand{
		Name:          instance,
		Login:         instance,
		Email:         instance + "@localhost.com",
		EmailVerified: false,
		OrgId:         orgQuery.Result.Id,
		Password:      RandomString(20),
	}

	cmd.Name = instance
	err := bus.Dispatch(&cmd)
	if err != nil {
		logger.Info("Create User "+instance+" Failed!", "err", err.Error())
		return err
	}
	return nil
}

func createOrg(instance string) error {
	cmd := models.CreateOrgCommand{}
	cmd.Name = instance
	err := bus.Dispatch(&cmd)
	if err != nil {
		logger.Info("Create Org "+instance+" Failed ", "err", err.Error())
		return err
	}
	return nil
}

func createFolder(instance string) (int64, error) {
	orgQuery := models.GetOrgByNameQuery{
		Name: instance,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+instance+" Failed: ", "err", err.Error())
		return 0, err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + instance + " Not Found !")
		return 0, fmt.Errorf("Query Org " + instance + " Not Found !")
	}

	s := dashboards.NewFolderService(orgQuery.Result.Id, &models.SignedInUser{
		Login: instance,
		Name:  instance,
	})

	cmd := models.CreateFolderCommand{
		Title: instance,
	}
	err := s.CreateFolder(&cmd)

	logger.Info("Create Folder Success")
	if err != nil {
		logger.Info("Create Folder " + instance + " Failed !")
		return 0, err
	}

	return cmd.Result.Id, nil
}

func createDataSource(orgname string) error {
	orgQuery := models.GetOrgByNameQuery{
		Name: orgname,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+orgname+" Failed: ", "err", err.Error())
		return err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + orgname + " Not Found !")
		return fmt.Errorf("Query Org " + orgname + " Not Found !")
	}

	cmd := models.AddDataSourceCommand{}
	cmd.OrgId = orgQuery.Result.Id
	cmd.Name = "Prometheus"
	cmd.Url = "http://prometheus.kube-system.svc.cluster.local:9090"
	cmd.Type = "prometheus"
	cmd.Access = "proxy"

	err := bus.Dispatch(&cmd)

	if err != nil {
		logger.Error("Create Prometheus DataSources Failed")
		return err
	}

	logger.Info("Create DataSource " + cmd.Result.Name + " Success!")
	return nil
}

func createDashboard(orgname, username string) error {
	userQuery := models.GetUserByLoginQuery{LoginOrEmail: username}

	if err := bus.Dispatch(&userQuery); err != nil {
		logger.Info("Query User "+username+" Failed ", "err", err.Error())
		return err
	}

	orgQuery := models.GetOrgByNameQuery{
		Name: orgname,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+username+" Failed: ", "err", err.Error())
		return err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + orgname + " Not Found !")
		return fmt.Errorf("Query Org " + orgname + " Not Found !")
	}

	user := userQuery.Result

	confPath := os.Getenv("CONF_PATH")
	dashboard, err := plugins.CreateDashboardFromFile(confPath, username)
	dashboard.Data.Set("title", username)
	dashboard.Data.Set("uid", username)
	dashboard.Title = username
	dashboard.Uid = username

	if err != nil {
		logger.Info("Generate Dashboard from json file Failed: ", err.Error())
		return err
	}

	saveCmd := models.SaveInstanceDashboardCommand{
		OrgId:        orgQuery.Result.Id,
		Dashboard:    dashboard.Data,
		UserId:       user.Id,
		RestoredFrom: 0,
	}

	saveCmd.Message = fmt.Sprintf("Restored from version %d", 0)
	saveCmd.FolderId = 0

	cmd := plugins.ImportInstanceDashboardCommand{
		OrgId: orgQuery.Result.Id,
		User: &models.SignedInUser{
			UserId:         1,
			Login:          "Admin",
			Email:          userQuery.Result.Email,
			OrgId:          1,
			IsGrafanaAdmin: true,
		},
		PluginId:  "",
		Path:      "",
		Inputs:    []plugins.ImportDashboardInput{},
		Overwrite: true,
		FolderId:  0,
		Dashboard: dashboard.Data,
	}

	if err := bus.Dispatch(&cmd); err != nil {
		return err
	}

	if err != nil {
		logger.Info("Importer Dashboard from json file Failed: ", err.Error())
		return err
	}

	return nil
}

// DELETE /instances/:instance  (Delete instances in grafana for nebula)
func DeleteInstances(c *models.ReqContext) Response {
	instance := c.Params(":instanceID")
	logger.Info("Delete Instance", "id", instance)

	err := deleteDataSource(instance)
	if err != nil {
		return Error(500, "Delete DataSource Failed", err)
	}

	logger.Info("Delete DataSource Success")
	err = deleteInstanceDashboard(instance)
	if err != nil {
		return Error(500, "Delete Dashboard Failed", err)
	}

	err = deleteUser(instance)
	if err != nil {
		return Error(500, "Delete User Failed", err)
	}

	err = deleteOrg(instance)
	if err != nil {
		return Error(500, "Delete Org Failed", err)
	}

	return JSON(200, map[string]string{})
}

func deleteDataSource(orgname string) error {
	orgQuery := models.GetOrgByNameQuery{
		Name: orgname,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+orgname+" Failed: ", "err", err.Error())
		return err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + orgname + " Not Found !")
		return fmt.Errorf("Query Org " + orgname + " Not Found !")
	}

	getCmd := &models.GetDataSourceByNameQuery{Name: "Prometheus", OrgId: orgQuery.Result.Id}
	if err := bus.Dispatch(getCmd); err != nil {
		if err == models.ErrDataSourceNotFound {
			logger.Error("DataSource Not Found")
			return err
		}
		return err
	}

	if getCmd.Result.ReadOnly {
		return fmt.Errorf("Have No this DataSource Right")
	}

	cmd := &models.DeleteDataSourceByNameCommand{Name: "Prometheus", OrgId: orgQuery.Result.Id}
	err := bus.Dispatch(cmd)
	if err != nil {
		logger.Error("Delete DataSource Failed")
		return err
	}

	return nil
}

func deleteUser(instance string) error {
	userQuery := models.GetUserByLoginQuery{LoginOrEmail: instance}

	if err := bus.Dispatch(&userQuery); err != nil {
		logger.Info("Query User "+instance+" Failed ", err.Error())
		return err
	}

	cmd := models.DeleteUserCommand{}
	cmd.UserId = userQuery.Result.Id

	err := bus.Dispatch(&cmd)
	if err != nil {
		logger.Info("Delete User " + instance + " Failed!")
		return err
	}
	return nil
}

func deleteOrg(instance string) error {
	orgQuery := models.GetOrgByNameQuery{
		Name: instance,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+instance+" Failed: ", err.Error())
		return err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + instance + " Not Found !")
		return fmt.Errorf("Query Org " + instance + " Not Found !")
	}

	cmd := models.DeleteOrgCommand{}
	cmd.Id = orgQuery.Result.Id
	err := bus.Dispatch(&cmd)
	if err != nil {
		logger.Info("Delete Org "+instance+" Failed ", err.Error())
		return err
	}

	return nil
}

func deleteInstanceDashboard(instance string) error {

	userQuery := models.GetUserByLoginQuery{LoginOrEmail: instance}

	if err := bus.Dispatch(&userQuery); err != nil {
		logger.Info("Query User "+instance+" Failed ", err.Error())
		return err
	}

	orgQuery := models.GetOrgByNameQuery{
		Name: instance,
	}

	if err := bus.Dispatch(&orgQuery); err != nil {
		logger.Info("Query Org "+instance+" Failed: ", err.Error())
		return err
	}

	if orgQuery.Result == nil {
		logger.Info("Query Org " + instance + " Not Found !")
		return fmt.Errorf("Query Org " + instance + " Not Found !")
	}

	id := orgQuery.Result.Id

	query := &search.FindPersistedDashboardsQuery{
		OrgId: id,
		Title: instance,
		SignedInUser: &models.SignedInUser{
			UserId: userQuery.Result.Id,
			OrgId:  userQuery.Result.OrgId,
		},
	}

	err := sqlstore.SearchDashboards(query)
	if err != nil {
		logger.Error("Get dashboards Failed! err: " + err.Error())
		return err
	}

	for _, id := range query.DashboardIds {
		err := sqlstore.DeleteDashboard(&models.DeleteDashboardCommand{
			OrgId: orgQuery.Result.Id,
			Id:    id,
		})

		if err != nil {
			logger.Error("Delete dashboard  Failed! err: "+err.Error(), "id", id)
		}
	}

	return nil
}

func RandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
