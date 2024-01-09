## defect-dojo-lib

### Arquitectura

En el siguiente diagrama se muesta como la libreria se comunica con los diferentes servicios


![Alt text](defect_dojo-lib.png)


### Configurar Conexion

Para enviar informacion a defect_dojo es neceario crear una conexion y se puede realizar con ayudad de modulo
Connect, este modulo  expone la funcionalidad para crear el objecto de conexion con los demas servicios con los cuales se integra la libreria.

El modulo DefectDojo expone funcionalides aplicalbes a la app defect-dojo como por ejemplo send_import_scan metodo que hace la ingesta de datos de los vulnerabilidades reportadas por aplicaciones externas.


# Example of use of defect-dojo module

    import os
    from devsecops_engine_utilities.defect_dojo import DefectDojo, ImportScanRequest, Connect

    path_file = os.path.dirname(os.path.realpath(__file__))

    if __name__ == "__main__":

     request: ImportScanRequest = Connect.cmdb(
        compact_remote_config_url=https://grupotest.visualstudio.com//_git/project?path=/directory/file.json,
        cmdb_mapping={"product_type_name": "","product_name": "nombreapp","tag_product": "nombreentorno","product_description": "","codigo_app": ""}
        personal_access_token="aidfjajia3249ajfdiadjfijtest",
        token_cmdb=settings.2398298jdfa89289uj389jr3atest,
        host_cmdb="http://localhost",
        expression="",
        token_defect_dojo="aijfiadsfoiajtest123",
        host_defect_dojo="http://localhost:8000",
        scan_type="test_file.json",
        engagement_name="ABC_TestCode",
        tags="",
        branch_tag="master",
    )

    response = DefectDojo.send_import_scan(request)

**compact_remote_config_url** es la direcion del archivo remoto (Azure repository) el cual debe contener este formato

        "types_product": {
        "engagement_name": "engagement_name_other",
        "engagement_name": "engagement_name_other2",
        }

**cmdb_mapping** diccionario de configuracion para relacionar las palabra claves de la informacion obtenida de la cmdb y la informacion que se ingresara a defect-dojo por ejemplo
la informacion de la cmdb puede ser algo como esto.
    [
    {
        "engagement_name_cmdb": "engagement",
        "producto_name_cmdb": "product",
        "product_type_cmdb": "product_type",
        "codigo_app": "test_129342",
    }
    ]
es decir que para este ejemplo el nombre del produc_type en defect-dojo sera el valor que traera la variable o key de la cmdb llamada product_type_cmdb y de la misma forma para el resto de campos.



### Example api Scan

Est libreria soporta la integracion de defect-dojo via sonar por medio de API, para este caso en espesifico no es necesario espesificar no como debe de suponerse el archivo de scaneo
lugo defect-dojo se conecta a las api de sonar de forma automatica simpre y cuando se halla echo una configuracion previamente de esta.

Antes de utilizar esta funcionalidad se debe asegurar de haber creado un api-scan-configuration

   request: ImportScanRequest = Connect.cmdb(
        compact_remote_config_url=https://grupotest.visualstudio.com//_git/project?path=/directory/file.json,
        cmdb_mapping={"product_type_name": "","product_name": "nombreapp","tag_product": "nombreentorno","product_description": "","codigo_app": ""}
        personal_access_token="aidfjajia3249ajfdiadjfijtest",
        token_cmdb=settings.2398298jdfa89289uj389jr3atest,
        host_cmdb="http://localhost",
        expression="",
        token_defect_dojo="aijfiadsfoiajtest123",
        host_defect_dojo="http://localhost:8000",
        scan_type="test_file.json",
        engagement_name="ABC_TestCode",
        tags="",
        branch_tag="master",
    )

    response = DefectDojo.send_import_scan(request)


https://dev.azure.com/{organization}/{project}/_git/{repository}

## run Integration test

In this module you will find the integration tests of the methods implemented in the library and it can also serve as documentation.

be located in the directory common_devsecops_lib and execute command

    python -m integrations_test.defect_dojo


## Config lauch.json of vscode

    {
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Integration test",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/common_devsecops_lib/test_integrations_defect_dojo.py",
            "console": "integratedTerminal",
            "justMyCode": true
        }
    ]
}
