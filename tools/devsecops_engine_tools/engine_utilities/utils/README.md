## Domain Language

This section is about how to transform a JSON file into Python objects and how we can use the utilities developed in this repository. First, we need to have a clear understanding of the structure of our JSON file, for example, if we have the following *product_types* in the following format:

    {
        "count": 1,
        "next": null,
        "previous": null,
        "results": [
            {
                "id": 1,
                "name": "product_type name test1",
                "description": null,
                "critical_product": false,
                "key_product": false,
                "updated": "2023-07-11T13:29:05.233277Z",
                "created": "2023-07-11T13:29:05.233290Z",
                "members": [
                    35
                ],
                "authorization_groups": []
            },
            {
                "id": 2,
                "name": "product_type name test2",
                "description": null,
                "critical_product": false,
                "key_product": false,
                "updated": "2023-07-11T13:29:05.233277Z",
                "created": "2023-07-11T13:29:05.233290Z",
                "members": [
                    35
                ],
                "authorization_groups": []
            }
        ],
        "prefetch": {}
    }

This example is the response from an endpoint to query *product_types* from *Defect-Dojo*. Now, the question is, how can we translate this into the domain language? First, you need to import the *FromDictMixin* class, which implements some methods that allow us to perform the transformation into the domain language. Then, you should create a class that represents this response as follows:

    import dataclasses
    from typing import List
    from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin

    @dataclasses.dataclass
    class ProductTypeList(FromDictMixin):
        count: int = 0
        next = None
        previous = None
        results: List[ProductType] = dataclasses.field(default_factory=list)
        prefetch = None

    To represent the list of *product_types*, it is necessary to create another class that represents that part of *JSON* as follows:

    @dataclasses.dataclass
    class ProductType(FromDictMixin):
        id: int = 0
        name: str = ""
        description: str = ""
        critical_product: bool = None
        key_product: bool = None
        updated: str = ""
        created: str = ""
        members: List[int] = dataclasses.field(default_factory=list)
        authorization_groups: List[None] = dataclasses.field(default_factory=list)

If, for example, this *ProductType* class were within a Product, it would be necessary to create a Product class. It is important to clarify that it is not necessary to implement all the attributes, you can include only those you consider necessary.

With this, we are ready to make the transformation into the domain language

### Using the *from_dict* method

To use the *from_dict* method, which is responsible for the JSON to Python object transformation, it is invoked as follows:

    product_type_list_object = ProductTypeList().from_dict(response.json())

With this, we will have our first Python object serialized from JSON.

### Using the *to_dict* method

This method is responsible for transforming a Python object into *JSON*.

    product_type_list_dict = ProductTypeList().to_dict(objeto)


# Logger

This utility allows extending the functionalities of the logger, such as changing the color depending on the logger type. It also enables logging to a text file when necessary.

A simple example of using this module is as follows:


    from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger

    logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()

    logger.info("info message")
    logger.warning("warning message")
    logger.error("error message")
    logger.critical("critical message")

Error-type loggers are displayed in red, warning-type in yellow, and others in white.

The variable *SETTINGS_LOGGER* has the following structure:


    {
        "debug": True,
        "log_file": False
    }

If the debug variable is active, the log messages will be displayed, otherwise, they will be deactivated.

If the log_file variable is active, a hidden ./log folder will be created, where logs will be recorded daily, separated by folders. Each folder will be named after the current date. In other words, a folder will be created daily, and within it, a log file will be created.

# Session Manager

Usage of the session wrapped in the custom class:
    session = SessionManager()

Example of a request using the session:
    response = session.get('https://www.example.com')

Performing more requests using the same session:
    response2 = session.post('https://www.example.com/submit', data={'key': 'value'})
