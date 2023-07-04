import dataclasses
import typing
import datetime
import enum
from inspect import isclass
from .name_conversion import camel_case_to_snake_case, snake_case_to_camel_case
from .datetime_parsing import iso_from_datetime, parse_iso_datetime


class FromDictMixin:
    @staticmethod
    def attribute_to_dict(attribute):
        if hasattr(attribute, "to_dict") and callable(attribute.to_dict):
            return getattr(attribute, "to_dict")()
        return attribute

    def to_dict(self):
        if self == {}:
            return self
        available_fields = {field.name: field for field in dataclasses.fields(self)}
        transformed_data = {}
        for field_name, field_type in available_fields.items():
            navitaire_key = snake_case_to_camel_case(field_name)
            attribute = getattr(self, field_name)
            if isinstance(attribute, list):
                transformed_data[navitaire_key] = []
                for element in attribute:
                    transformed_data[navitaire_key].append(FromDictMixin.attribute_to_dict(element))
            elif isinstance(attribute, dict):
                transformed_data[navitaire_key] = {}
                for key, element in attribute.items():
                    transformed_data[navitaire_key][key] = FromDictMixin.attribute_to_dict(element)
            elif isinstance(attribute, enum.Enum):
                transformed_data[navitaire_key] = attribute.value
            elif isinstance(attribute, datetime.datetime):
                transformed_data[navitaire_key] = iso_from_datetime(attribute)
            else:
                transformed_data[navitaire_key] = FromDictMixin.attribute_to_dict(attribute)
        return transformed_data

    @classmethod
    def from_dict(cls, data):
        built_in_types = (int, str, bool, float)
        available_fields = {field.name: field for field in dataclasses.fields(cls)}
        transformed_data = {}
        for key, value in data.items():
            internal_key = camel_case_to_snake_case(key)
            if internal_key in available_fields.keys() and value:
                matching_internal_field = available_fields[internal_key]
                if matching_internal_field.type in built_in_types:
                    internal_value = value
                elif matching_internal_field.type == datetime.datetime and value:
                    internal_value = parse_iso_datetime(value)
                elif isclass(matching_internal_field.type) and issubclass(matching_internal_field.type, enum.Enum):
                    internal_value = matching_internal_field.type(value)
                elif hasattr(matching_internal_field.type, "from_dict") and callable(
                    matching_internal_field.type.from_dict
                ):
                    internal_value = matching_internal_field.type.from_dict(value)
                elif (
                    isinstance(matching_internal_field.type, typing._GenericAlias)
                    and matching_internal_field.type.__origin__ == list
                ):
                    value_class = matching_internal_field.type.__args__[0]
                    internal_value = []
                    if hasattr(value_class, "from_dict") and callable(value_class.from_dict):
                        internal_value = [value_class.from_dict(v) for v in value]
                    else:
                        internal_value = [v for v in value]
                elif (
                    isinstance(matching_internal_field.type, typing._GenericAlias)
                    and matching_internal_field.type.__origin__ == dict
                ):
                    value_class = matching_internal_field.type.__args__[1]
                    internal_value = {}
                    if hasattr(value_class, "from_dict") and callable(value_class.from_dict):
                        internal_value = {k: value_class.from_dict(v) for k, v in value.items()}
                    else:
                        internal_value = value
                else:
                    internal_value = None
                if internal_value:
                    transformed_data[internal_key] = internal_value
        return cls(**transformed_data)
