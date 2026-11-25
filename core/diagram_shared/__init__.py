"""Offline, evidence-derived NetConverter diagrams. No host or cloud dependencies."""
from .model import SCHEMA, VERSION, build_diagram
from .render import (render, icon_svg, diagram_bundle, reportlab_flowables,
                     append_fpdf, html_overview)

__all__ = ['SCHEMA', 'VERSION', 'build_diagram', 'render', 'icon_svg',
           'diagram_bundle', 'reportlab_flowables', 'append_fpdf', 'html_overview', 'png_pages']

from .render import png_pages
