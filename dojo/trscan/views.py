import logging
import mimetypes
import os
import re
import urllib.parse
from datetime import datetime, timedelta

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.http import Http404, HttpResponseRedirect, HttpResponseForbidden, JsonResponse
from django.http import HttpResponse
from django_filters.filters import _truncate
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.db.models import Q

from dojo.celery import app
from dojo.endpoint.views import get_endpoint_ids
from dojo.filters import ReportFindingFilter, ReportAuthedFindingFilter, EndpointReportFilter, ReportFilter, \
    EndpointFilter, now
from dojo.forms import ReportOptionsForm, DeleteReportForm
from dojo.models import Product_Type, Finding, Product, Engagement, Test, \
    Dojo_User, Endpoint, Report, Risk_Acceptance
from dojo.trscan.widgets import CoverPage, PageBreak, TableOfContents, WYSIWYGContent, FindingList, EndpointList, \
    CustomReportJsonForm, TrscanOptions, report_widget_factory
from dojo.tasks import async_pdf_report, async_custom_pdf_report
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting, get_period_counts_legacy, Product_Tab, \
    get_words_for_field, redirect
from dojo.user.helper import check_auth_users_list
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_permission_or_403

logger = logging.getLogger(__name__)


def down(request):
    return render(request, 'disabled.html')


def trscan_url_resolver(request):
    try:
        url_resolver = request.META['HTTP_X_FORWARDED_PROTO'] + "://" + request.META['HTTP_X_FORWARDED_FOR']
    except:
        hostname = request.META['HTTP_HOST']
        port_index = hostname.find(":")
        if port_index != -1:
            url_resolver = request.scheme + "://" + hostname[:port_index]
        else:
            url_resolver = request.scheme + "://" + hostname
    return url_resolver + ":" + request.META['SERVER_PORT']


def trscan(request):
    add_breadcrumb(title="Static Analysis", top_level=True, request=request)
    findings = Finding.objects.all()
    findings = ReportAuthedFindingFilter(request.GET, queryset=findings)
    endpoints = Endpoint.objects.filter(finding__active=True,
                                        finding__verified=True,
                                        finding__false_p=False,
                                        finding__duplicate=False,
                                        finding__out_of_scope=False,
                                        ).distinct()
    ids = get_endpoint_ids(endpoints)

    endpoints = Endpoint.objects.filter(id__in=ids)

    endpoints = EndpointFilter(request.GET, queryset=endpoints, user=request.user)
    in_use_widgets = [TrscanOptions(request=request)]
    available_widgets = [CoverPage(request=request),
                         TableOfContents(request=request),
                         WYSIWYGContent(request=request),
                         FindingList(request=request, findings=findings)]
    return render(request,
                  'dojo/TRScan.html',
                  {"available_widgets": available_widgets,
                   "in_use_widgets": in_use_widgets})

def custom_report(request):
    # saving the report
    form = CustomReportJsonForm(request.POST)
    host = report_url_resolver(request)
    if form.is_valid():
        selected_widgets = report_widget_factory(json_data=request.POST['json'], request=request, user=request.user,
                                                 finding_notes=False, finding_images=False, host=host)
        report_name = 'Custom PDF Report: ' + request.user.username
        report_format = 'AsciiDoc'
        finding_notes = True
        finding_images = True

        if 'report-options' in selected_widgets:
            options = selected_widgets['report-options']
            report_name = 'Custom PDF Report: ' + options.report_name
            report_format = options.report_type
            finding_notes = (options.include_finding_notes == '1')
            finding_images = (options.include_finding_images == '1')

        selected_widgets = report_widget_factory(json_data=request.POST['json'], request=request, user=request.user,
                                                 finding_notes=finding_notes, finding_images=finding_images, host=host)

        if report_format == 'PDF':
            report = Report(name=report_name,
                            type="Custom",
                            format=report_format,
                            requester=request.user,
                            task_id='tbd',
                            options=request.POST['json'])
            report.save()
            async_custom_pdf_report.delay(report=report,
                                          template="dojo/custom_pdf_report.html",
                                          filename="custom_pdf_report.pdf",
                                          host=host,
                                          user=request.user,
                                          uri=request.build_absolute_uri(report.get_url()),
                                          finding_notes=finding_notes,
                                          finding_images=finding_images)
            messages.add_message(request, messages.SUCCESS,
                                 'Your report is building.',
                                 extra_tags='alert-success')

            return HttpResponseRedirect(reverse('reports'))
        elif report_format == 'AsciiDoc':
            widgets = list(selected_widgets.values())
            return render(request,
                          'dojo/custom_asciidoc_report.html',
                          {"widgets": widgets,
                           "host": host,
                           "finding_notes": finding_notes,
                           "finding_images": finding_images,
                           "user_id": request.user.id})
        elif report_format == 'HTML':
            widgets = list(selected_widgets.values())
            return render(request,
                          'dojo/custom_html_report.html',
                          {"widgets": widgets,
                           "host": host,
                           "finding_notes": finding_notes,
                           "finding_images": finding_images,
                           "user_id": request.user.id})
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()



def validate_date(date, filter_lookup):
    # Today
    if date == 1:
        filter_lookup['date__year'] = now().year
        filter_lookup['date__month'] = now().month
        filter_lookup['date__day'] = now().day
    # Past 7 Days
    elif date == 2:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=7))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))
    # Past 30 Days
    elif date == 3:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=30))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))
    # Past 90 Days
    elif date == 4:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=90))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))
    # Current Month
    elif date == 5:
        filter_lookup['date__year'] = now().year
        filter_lookup['date__month'] = now().month
    # Current Year
    elif date == 6:
        filter_lookup['date__year'] = now().year
    # Past Year
    elif date == 7:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=365))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))


def validate(field, value):
    validated_field = field
    validated_value = None
    # Boolean values
    if value in ['true', 'false', 'unknown']:
        if value == 'true':
            validated_value = True
        elif value == 'false':
            validated_value = False
    # Tags (lists)
    elif 'tags' in field:
        validated_field = value.split(', ')
        validated_field = field + '__in'
    else:
        # Integer (ID) values
        try:
            validated_value = int(value)
            if field not in ['nb_occurences', 'nb_occurences', 'date', 'cwe']:
                validated_field = field + '__id'
        except ValueError:
            # Okay it must be a string
            validated_value = None if not len(value) else value
    return (validated_field, validated_value)

def RunStatic(request):

    main="wine srcheck.bat " + in_use_widgets
    file = os.path.join(os.path.dirname(os.path.abspath(__file__)), main)
    f = os.popen(file)    
    data = f.readlines()    
    f.close() 



