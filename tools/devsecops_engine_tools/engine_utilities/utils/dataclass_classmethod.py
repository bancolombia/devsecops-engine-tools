import dataclasses
import typing
import datetime
import enum
from inspect import isclass
from typing import get_type_hints
from .alias import Alias
from .name_conversion import camel_case_to_snake_case, snake_case_to_camel_case
from .datetime_parsing import iso_from_datetime, parse_iso_datetime


class FromDictMixin:
    _exclude_none: bool = False

    @staticmethod
    def _resolve_union_type(union_type):
        """Extract the non-None type from Optional/Union types (e.g., Optional[X] -> X)"""
        if hasattr(union_type, '__origin__') and union_type.__origin__ is typing.Union:
            args = union_type.__args__
            # Filter out NoneType to get the actual type
            non_none_types = [arg for arg in args if arg is not type(None)]
            if non_none_types:
                return non_none_types[0]
        return union_type

    @staticmethod
    def attribute_to_dict(attribute):
        if hasattr(attribute, "to_dict") and callable(attribute.to_dict):
            return getattr(attribute, "to_dict")()
        return attribute

    @staticmethod
    def _resolve_key(field_name, hints):
        hint = hints.get(field_name)
        if hasattr(hint, "__metadata__"):
            for meta in hint.__metadata__:
                if isinstance(meta, Alias):
                    return meta.name
        return snake_case_to_camel_case(field_name)

    def to_dict(self):
        if self == {}:
            return self
        hints = get_type_hints(self.__class__, include_extras=True)
        available_fields = {field.name: field for field in dataclasses.fields(self)}
        transformed_data = {}
        for field_name, field_type in available_fields.items():
            if field_name.startswith("_"):
                continue
            attribute = getattr(self, field_name)
            if self._exclude_none and attribute is None:
                continue
            key = self._resolve_key(field_name, hints)
            transformed_data[key] = self._transform_field_value(attribute)
        return transformed_data

    @staticmethod
    def _transform_field_value(attribute):
        if isinstance(attribute, list):
            return [FromDictMixin.attribute_to_dict(element) for element in attribute]
        if isinstance(attribute, dict):
            return {
                k: FromDictMixin.attribute_to_dict(element)
                for k, element in attribute.items()
            }
        if isinstance(attribute, enum.Enum):
            return attribute.value
        if isinstance(attribute, datetime.datetime):
            return iso_from_datetime(attribute)
        return FromDictMixin.attribute_to_dict(attribute)

    @classmethod
    def from_dict(cls, data):
        built_in_types = (int, str, bool, float)
        available_fields = {field.name: field for field in dataclasses.fields(cls)}
        transformed_data = {}
        for key, value in data.items():
            internal_key = camel_case_to_snake_case(key)
            if internal_key not in available_fields or value is None:
                continue
            matching_internal_field = available_fields[internal_key]
            # Resolve Union/Optional types to get the actual type
            field_type = cls._resolve_union_type(matching_internal_field.type)
            internal_value = cls._resolve_field_value(field_type, value, built_in_types)
            if internal_value is not None:
                transformed_data[internal_key] = internal_value
        return cls(**transformed_data)

    @classmethod
    def _resolve_field_value(cls, field_type, value, built_in_types):
        if field_type in built_in_types:
            return value
        if field_type == datetime.datetime and value:
            return parse_iso_datetime(value)
        if isclass(field_type) and issubclass(field_type, enum.Enum):
            return field_type(value)
        if hasattr(field_type, "from_dict") and callable(field_type.from_dict):
            return field_type.from_dict(value)
        if isinstance(field_type, typing._GenericAlias) and field_type.__origin__ == list:
            return cls._resolve_list_field_value(field_type, value)
        if isinstance(field_type, typing._GenericAlias) and field_type.__origin__ == dict:
            return cls._resolve_dict_field_value(field_type, value)
        return None

    @staticmethod
    def _resolve_list_field_value(field_type, value):
        value_class = field_type.__args__[0]
        if hasattr(value_class, "from_dict") and callable(value_class.from_dict):
            return [value_class.from_dict(v) for v in value]
        return [v for v in value]

    @staticmethod
    def _resolve_dict_field_value(field_type, value):
        value_class = field_type.__args__[1]
        if hasattr(value_class, "from_dict") and callable(value_class.from_dict):
            return {k: value_class.from_dict(v) for k, v in value.items()}
        return value
