import django_filters
from django.contrib.auth import get_user_model
from django.db.models import Q
from .models import Task, Tag

User = get_user_model()

class TaskFilter(django_filters.FilterSet):
    # custom:
    deadline_after = django_filters.DateTimeFilter(field_name="deadline", lookup_expr="gte")
    deadline_before = django_filters.DateTimeFilter(field_name="deadline", lookup_expr="lte")
    # GET /api/tasks/?deadline_after=2025-04-10T00:00:00&deadline_before=2025-04-20T23:59:59
    # owner = django_filters.ModelChoiceFilter(field_name='owner', queryset=User.objects.all()) make auto
    # GET /api/tasks/?owner=3
    owner__username = django_filters.CharFilter(field_name="owner__username", lookup_expr="iexact")
    executor__username = django_filters.CharFilter(field_name="executor__username", lookup_expr="iexact")
    # GET /api/tasks/?owner__username=johndoe
    # executor = django_filters.ModelMultipleChoiceFilter(
    #     field_name='executor',
    #     to_field_name='id',
    #     queryset=User.objects.all()
    # )  # GET /api/tasks/?executor=1&executor=3
    tags = django_filters.ModelMultipleChoiceFilter(
        field_name='tags',
        to_field_name='id',
        queryset=Tag.objects.all()
    )  # GET /api/tasks/?tags=2&tags=4

    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = Task
        fields = ['status', 'priority',
                  "deadline_after", "deadline_before",
                  'owner', "owner__username",
                  'executor', "tags", "search" ]  # here exact or custom

    def filter_search(self, queryset, name, value):  # name	- filter name "search"
        return queryset.filter(
            Q(title__icontains=value) |
            Q(description__icontains=value) |
            Q(comments__text__icontains=value) |
            Q(tags__name__icontains=value) |
            Q(category__name__icontains=value)
        ).distinct()

