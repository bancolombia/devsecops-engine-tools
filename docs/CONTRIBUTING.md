# How to contribute

To contribute you must be first [configure you enviroment](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/docs/ENVIROMENT_CONFIGURATION.md):

The naming style is based on [PEP 8](https://peps.python.org/pep-0008/) which means that the `Snake Case` style is used for function, variable and module names, and `Camel Case` is used for class naming.

Examples `Camel Case`:
```python
class Test(Model):
    def foo(self, b: B): ...
```


Examples `Snake Case`:
```python
#variables and functions
def long_function_name(
        var_one, var_two, var_three,
        var_four):
    print(var_one)
```

# Naming semantics
For naming, the guideline for names to be ``readable, clear and concise`` should be followed.

# Context-sensitive appointment

As mentioned in the previous section, `snake case` should be used for variable declaration.

##  Private variables

```python
class Test(Model):
    _private_variable = "test" ...
```

# Standard naming of packages and modules

Packages (directories) and modules (.py files) must be lowercase.

```
└─ package_xyz
   │   
   ├── module1.py
   ├── module2.py
   ├── .... 
```

<table>
  <tbody>
    <tr style="background-color:#fef0cc;color: rgba(120,103,40,255);border-style: hidden" id="ROW1">
      <td><b>⚠️ Important </b></td>
    </tr>
    <tr style="background-color:#fef0cc;color: rgba(120,103,40,255);border-style: hidden" id="ROW2">
      <td>All source code and internal components of the project should be written in <b>English</b>.
       </td>
    </tr>
  </tbody>
</table>

