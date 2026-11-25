"""One offline scene, five formats. SVG masters are trusted bundled assets only."""
from __future__ import annotations

import base64
from functools import lru_cache
import hashlib
from html import escape
import io
import json
import math
import re
from pathlib import Path
import textwrap
from urllib.parse import quote
import xml.etree.ElementTree as ET

from .model import canonical, SCHEMA, VERSION

ROOT = Path(__file__).parent
INK = '#24282f'
BLUE = '#2563eb'
MUTED = '#647080'
WIDTH, HEIGHT = 760, 1080
CARD_W, CARD_H = 300, 128
MEDIA = {'svg': 'image/svg+xml', 'png': 'image/png', 'pdf': 'application/pdf',
         'drawio': 'application/vnd.jgraph.mxfile', 'json': 'application/json'}


@lru_cache(maxsize=48)
def icon_svg(identifier, monochrome=False):
    """Names are a closed catalog, never filesystem paths from a caller."""
    catalog = json.loads((ROOT / 'icons.json').read_text())
    if identifier not in catalog['icons']:
        raise ValueError('Unknown NetConverter icon')
    return (ROOT / ('monochrome' if monochrome else 'assets') / (identifier + '.svg')).read_text()


@lru_cache(maxsize=1)
def _font():
    return base64.b64encode((ROOT / 'fonts/Vera.ttf').read_bytes()).decode()


@lru_cache(maxsize=1)
def _font_chars():
    # ReportLab is already a host PDF dependency. Standard-library SVG-only
    # hosts retain readable explicit escapes rather than missing-glyph boxes.
    try:
        from reportlab.pdfbase.ttfonts import TTFont
        return frozenset(TTFont('NCDiagram', str(ROOT / 'fonts/Vera.ttf')).face.charToGlyph)
    except ImportError:
        return frozenset(range(32, 256))


def visible(value):
    return ''.join(c if ord(c) in _font_chars() or c in '\n\t' else '\\u%04x' % ord(c) for c in str(value))


def _text(x, y, value, size=14, color=INK, weight='normal', anchor='start'):
    return f'<text x="{x}" y="{y}" font-family="NCDiagram" font-size="{size}" font-weight="{weight}" fill="{color}" text-anchor="{anchor}">{escape(visible(value))}</text>'


@lru_cache(maxsize=1)
def _glyph_widths():
    try:
        from reportlab.pdfbase.ttfonts import TTFont
        return TTFont('NCDiagramMetrics', str(ROOT / 'fonts/Vera.ttf')).face.charWidths
    except ImportError:
        return {}


def _lines(value, width, maximum, font_size=10):
    lines = []
    for line in visible(value).splitlines() or ['']:
        # Bound physical text width too: WWWW must not overflow where iiii fits.
        budget = width * font_size * 0.55
        for chunk in textwrap.wrap(line, width=width, break_long_words=True) or ['']:
            current, used = '', 0.0
            for char in chunk:
                advance = _glyph_widths().get(ord(char), 1000) / 1000 * font_size * 1.1
                if current and used + advance > budget:
                    lines.append(current.rstrip())
                    current, used = '', 0.0
                current += char
                used += advance
            lines.append(current.strip())
    if len(lines) > maximum:
        return lines[:maximum - 1] + [lines[maximum - 1][:max(1, width - 3)] + '...'], True
    return lines, False


def _validate(diagram):
    if diagram.get('schema') != SCHEMA:
        raise ValueError('Unsupported diagram schema')
    nodes, edges = diagram.get('nodes', []), diagram.get('edges', [])
    if len(nodes) > 1000 or len(edges) > 10000:
        raise ValueError('Diagram exceeds rendering bounds')
    ids = [n['id'] for n in nodes]
    if len(set(ids)) != len(ids) or any(e['source'] not in ids or e['target'] not in ids for e in edges):
        raise ValueError('Invalid diagram references')


def _scenes(diagram):
    """Bounded 2-column pages; cross-page edges become explicit references."""
    _validate(diagram)
    columns = [[] for _ in range(2)]
    for node in diagram['nodes']:
        columns[min(1, max(0, int(node.get('level', 1))) // 2)].append(node)
    count = max(1, max(math.ceil(len(c) / 4) for c in columns))
    locations = {}
    for col, members in enumerate(columns):
        for row, node in enumerate(members):
            locations[node['id']] = {'x': 48 + col * 364, 'y': 208 + (row % 4) * 164,
                                     'page': row // 4, 'node': node}
    return count, locations


def _svg_page(diagram, page, count, locations, monochrome=False):
    accent = INK if monochrome else BLUE
    metadata = {'id': diagram['id'], 'provenance': diagram['provenance'], 'coverage': diagram['coverage']}
    out = ['<metadata>' + escape(canonical(metadata).decode()) + '</metadata>', f'<rect width="{WIDTH}" height="{HEIGHT}" fill="white"/>',
           '<style>@font-face{font-family:NCDiagram;src:url(data:font/ttf;base64,' + _font() + ')}</style>',
           _text(48, 46, 'NetConverter', 20, weight='bold'),
           _text(WIDTH - 48, 46, 'PRECISION OUTLINE / ' + VERSION, 11, MUTED, anchor='end'),
           _text(48, 100, diagram['title'], 27, weight='bold')]
    provenance = diagram.get('provenance', {})
    identity = ' | '.join(f'{key}: {provenance[key]}' for key in ('finding_id', 'job_id', 'revision', 'scope', 'view') if provenance.get(key) is not None)
    lines, _ = _lines(identity or 'Selected snapshot / provenance supplied by host', 90, 2, 11)
    for i, line in enumerate(lines):
        out.append(_text(48, 128 + 17 * i, line, 11, MUTED))
    out.append(f'<path d="M48 174 H{WIDTH-48}" stroke="#e6e9ef"/>')
    continuations, clipped_labels = [], False
    for edge in diagram['edges']:
        a, b = locations[edge['source']], locations[edge['target']]
        if a['page'] != page and b['page'] != page:
            continue
        if a['page'] != b['page']:
            other = b if a['page'] == page else a
            continuations.append(f'{a["node"]["label"]} -> {b["node"]["label"]}: page {other["page"] + 1}')
            continue
        left_to_right = a['x'] <= b['x']
        ax = a['x'] + (CARD_W if left_to_right else 0)
        bx = b['x'] + (0 if left_to_right else CARD_W)
        ay, by = a['y'] + CARD_H // 2, b['y'] + CARD_H // 2
        if a['x'] == b['x']:
            ax = bx = a['x'] + CARD_W
            mid = ax + 16
        else:
            mid = (ax + bx) / 2
        dash = ' stroke-dasharray="5 4"' if edge.get('basis') in ('unknown', 'inferred', 'modeled') else ''
        out.append(f'<path d="M{ax} {ay} H{mid} V{by} H{bx}" fill="none" stroke="{MUTED}" stroke-width="1.2"{dash}/>')
        direction = -1 if left_to_right else 1
        out.append(f'<path d="M{bx+direction*5} {by-3} L{bx} {by} L{bx+direction*5} {by+3}" fill="none" stroke="{MUTED}"/>')
    for location in locations.values():
        if location['page'] != page:
            continue
        n, x, y = location['node'], location['x'], location['y']
        out.append(f'<g><title>{escape(n["label"] + " / " + n.get("detail", ""))}</title><rect x="{x}" y="{y}" width="{CARD_W}" height="{CARD_H}" rx="5" fill="white" stroke="#d9dfe7"/>')
        raw = icon_svg(n['icon'], monochrome)
        root = ET.fromstring(raw)
        # Only the approved masters enter here; never render caller SVG.
        children = ''.join(ET.tostring(child, encoding='unicode') for child in root)
        out.append(f'<g transform="translate({x+13},{y+15}) scale({40/48})">{children}</g>')
        lines, clipped = _lines(n['label'], 23, 2, 16)
        clipped_labels |= clipped
        for i, line in enumerate(lines):
            out.append(_text(x + 65, y + 28 + i * 21, line, 16, weight='bold'))
        detail, clipped = _lines(n.get('detail', ''), 35, 2, 13)
        clipped_labels |= clipped
        for i, line in enumerate(detail):
            out.append(_text(x + 13, y + 82 + 17 * i, line, 13, MUTED))
        out.append(_text(x + CARD_W - 10, y + 121, n.get('change') or n.get('basis', ''), 9, accent, anchor='end'))
        out.append('</g>')
    if not diagram['nodes']:
        out.append(_text(48, 240, 'Diagram unavailable for the selected evidence', 20))
    coverage = diagram['coverage']
    notes = ['Coverage: ' + coverage['status'] + f' | {len(diagram["nodes"])}/{coverage["total_nodes"]} nodes | {len(diagram["edges"])}/{coverage["total_edges"]} relationships.']
    notes += coverage.get('reasons', [])
    if any(visible(n['label'] + n.get('detail', '')) != n['label'] + n.get('detail', '') for n in diagram['nodes']):
        notes.append('Unsupported font glyphs shown as Unicode escapes. Original labels remain in JSON, SVG titles and draw.io.')
    if continuations:
        notes.append(f'{len(continuations)} cross-page relationships. Complete endpoints and evidence: diagram JSON / draw.io.')
        notes.extend(continuations[:2])
    if clipped_labels:
        notes.append('Long labels abbreviated on this page; full text is in diagram JSON, SVG titles and editable draw.io.')
    # All reasons remain in the semantic document; visual summaries disclose
    # bounded captions instead of silently suppressing important provenance.
    lines, clipped = _lines('\n'.join(notes), 108, 8)
    for i, line in enumerate(lines):
        out.append(_text(48, 878 + i * 15, line, 10, MUTED))
    if clipped:
        out.append(_text(48, 1005, 'Additional coverage notes in the diagram JSON.', 10, MUTED))
    out.append(f'<path d="M48 1024 H{WIDTH-48}" stroke="#e6e9ef"/>')
    out.append(_text(48, 1053, 'NetConverter — by ValeronLabs LLC | Derived documentation.', 9, MUTED))
    out.append(_text(WIDTH - 48, 1053, f'{diagram["id"][-12:]} / {page+1} of {count}', 10, MUTED, anchor='end'))
    return ''.join(out)


def svg_pages(diagram, monochrome=False):
    count, locations = _scenes(diagram)
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">' +
            _svg_page(diagram, page, count, locations, monochrome) + '</svg>' for page in range(count)]


def _drawio(diagram):
    count, locations = _scenes(diagram)
    root = ET.Element('mxfile', {'host': 'NetConverter', 'version': VERSION, 'type': 'device'})
    page = ET.SubElement(root, 'diagram', {'id': diagram['id'], 'name': diagram['title'],
                                         'ncProvenance': canonical(diagram['provenance']).decode(),
                                         'ncCoverage': canonical(diagram['coverage']).decode(),
                                         'ncNotice': diagram['notice']})
    model = ET.SubElement(page, 'mxGraphModel', {'page': '1', 'pageWidth': str(WIDTH), 'pageHeight': str(HEIGHT)})
    cells = ET.SubElement(model, 'root')
    ET.SubElement(cells, 'mxCell', {'id': '0'})
    ET.SubElement(cells, 'mxCell', {'id': '1', 'parent': '0'})
    for n in diagram['nodes']:
        loc = locations[n['id']]
        style = 'shape=image;verticalLabelPosition=bottom;verticalAlign=top;imageAspect=1;html=0;fontFamily=Arial;fontSize=12;image=data:image/svg+xml,' + quote(icon_svg(n['icon']), safe='') + ';'
        cell = ET.SubElement(cells, 'mxCell', {'id': n['id'], 'value': n['label'] + '\n' + n.get('detail', ''),
                    'style': style, 'vertex': '1', 'parent': '1', 'ncEvidence': canonical(n['evidence_refs']).decode(), 'ncBasis': n['basis']})
        ET.SubElement(cell, 'mxGeometry', {'x': str(loc['x'] + 90), 'y': str(loc['y'] + loc['page'] * HEIGHT),
                                         'width': '64', 'height': '64', 'as': 'geometry'})
    for e in diagram['edges']:
        cell = ET.SubElement(cells, 'mxCell', {'id': e['id'], 'value': e['label'], 'edge': '1', 'parent': '1',
                    'source': e['source'], 'target': e['target'], 'style': 'edgeStyle=orthogonalEdgeStyle;html=0;endArrow=block;strokeColor=#647080;',
                    'ncEvidence': canonical(e['evidence_refs']).decode(), 'ncBasis': e['basis']})
        ET.SubElement(cell, 'mxGeometry', {'relative': '1', 'as': 'geometry'})
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def _drawing(svg):
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from svglib.svglib import svg2rlg
    if 'NCDiagram' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('NCDiagram', str(ROOT / 'fonts/Vera.ttf')))
        pdfmetrics.registerFontFamily('NCDiagram', normal='NCDiagram', bold='NCDiagram', italic='NCDiagram', boldItalic='NCDiagram')
    # Embedded CSS is for standalone SVG; ReportLab uses the same bundled font.
    svg = re.sub(r'<style>.*?</style>', '', svg, flags=re.S)
    drawing = svg2rlg(io.BytesIO(svg.encode()))
    # svglib interprets CSS pixels as 0.75 points. Restore scene coordinates
    # so standalone PDF and embedded reports share the SVG/PNG geometry.
    drawing.scale(WIDTH / drawing.width, HEIGHT / drawing.height)
    drawing.width, drawing.height = WIDTH, HEIGHT
    return drawing


def render(diagram, format='svg', *, monochrome=False):
    _validate(diagram)
    if format not in MEDIA:
        raise ValueError('Unsupported diagram format')
    if format == 'json':
        return canonical(diagram) + b'\n'
    if format == 'drawio':
        return _drawio(diagram)
    pages = svg_pages(diagram, monochrome)
    if format in ('svg', 'png'):
        height = HEIGHT * len(pages)
        body = ''.join(f'<g transform="translate(0,{i * HEIGHT})">{p[p.index(">")+1:p.rindex("</svg>")]}</g>' for i, p in enumerate(pages))
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}">{body}</svg>'.encode()
        if format == 'svg':
            return svg
        import cairosvg
        # Bound memory even for very large detail selections. PDF/SVG/draw.io
        # retain full scale; PNG is a raster overview of the same scene.
        scale = min(1.0, 12000 / height)
        raster = cairosvg.svg2png(bytestring=_outlined(svg.decode()), scale=scale)
        from PIL import Image
        from PIL.PngImagePlugin import PngInfo
        metadata = PngInfo()
        metadata.add_text('nc.diagram', canonical({'id': diagram['id'], 'provenance': diagram['provenance'], 'coverage': diagram['coverage']}).decode())
        out = io.BytesIO()
        with Image.open(io.BytesIO(raster)) as picture:
            picture.save(out, format='PNG', pnginfo=metadata)
        return out.getvalue()
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.graphics import renderPDF
    out = io.BytesIO()
    canvas = Canvas(out, pagesize=(WIDTH, HEIGHT), invariant=1, pageCompression=1)
    canvas.setTitle(diagram['title'])
    canvas.setAuthor('NetConverter — by ValeronLabs LLC')
    canvas.setSubject(canonical({'id': diagram['id'], 'provenance': diagram['provenance'], 'coverage': diagram['coverage']}).decode())
    for page in pages:
        renderPDF.draw(_drawing(page), canvas, 0, 0)
        canvas.showPage()
    canvas.save()
    return out.getvalue()


def diagram_bundle(diagrams, formats=('svg', 'png', 'pdf', 'drawio', 'json')):
    files, artifacts, errors = {}, [], []
    for d in diagrams:
        for fmt in formats:
            if fmt not in MEDIA:
                raise ValueError('Unsupported diagram format')
            name = f'diagrams/{d["kind"]}-{d["side"]}-{d["id"][-12:]}.{fmt}'
            try:
                content = render(d, fmt)
            except Exception as exc:
                errors.append({'diagram_id': d['id'], 'format': fmt, 'status': 'unavailable',
                               'reason': 'Diagram artifact rendering failed: ' + type(exc).__name__})
                continue
            files[name] = content
            artifacts.append({'path': name, 'sha256': hashlib.sha256(content).hexdigest(),
                              'size_bytes': len(content), 'media_type': MEDIA[fmt], 'diagram_id': d['id'],
                              'kind': d['kind'], 'side': d['side'], 'provenance': d['provenance']})
    files['diagrams/manifest.json'] = canonical({'schema': 'nc.diagram-manifest.v1', 'library_version': VERSION,
                                               'artifacts': artifacts, 'errors': errors}) + b'\n'
    return files


def reportlab_flowables(diagrams, *, width=480, max_height=650):
    from reportlab.platypus import PageBreak
    result = []
    for d in diagrams:
        for svg in svg_pages(d):
            drawing = _drawing(svg)
            # Standard A4 content area. Dedicated pages preserve layout.
            factor = min(width / WIDTH, max_height / HEIGHT)
            drawing.scale(factor, factor)
            drawing.width *= factor
            drawing.height *= factor
            result.extend([PageBreak(), drawing])
    return result


def _outlined(svg):
    """Convert text to the embedded font's paths for Cairo, independent of OS fonts."""
    from fontTools.ttLib import TTFont
    from fontTools.pens.svgPathPen import SVGPathPen
    font = TTFont(str(ROOT / 'fonts/Vera.ttf'))
    glyphs, cmap = font.getGlyphSet(), font.getBestCmap()
    namespace = '{http://www.w3.org/2000/svg}'
    root = ET.fromstring(re.sub(r'<style>.*?</style>', '', svg, flags=re.S))
    for parent in list(root.iter()):
        for element in list(parent):
            if element.tag != namespace + 'text':
                continue
            content = element.text or ''
            scale = float(element.get('font-size', 14)) / font['head'].unitsPerEm
            names = [cmap.get(ord(c), '.notdef') for c in content]
            width = sum(font['hmtx'][name][0] for name in names) * scale
            x, y = float(element.get('x', 0)), float(element.get('y', 0))
            anchor = element.get('text-anchor')
            x -= width if anchor == 'end' else width / 2 if anchor == 'middle' else 0
            group = ET.Element(namespace + 'g', {'fill': element.get('fill', INK)})
            ET.SubElement(group, namespace + 'title').text = content
            for name in names:
                pen = SVGPathPen(glyphs)
                glyphs[name].draw(pen)
                ET.SubElement(group, namespace + 'path', {'d': pen.getCommands(),
                    'transform': f'translate({x},{y}) scale({scale},{-scale})'})
                x += font['hmtx'][name][0] * scale
            parent.insert(list(parent).index(element), group)
            parent.remove(element)
    font.close()
    return ET.tostring(root, encoding='utf-8')


def png_pages(diagram, *, monochrome=False):
    """Scoped full-size page scenes for DOCX and other paginated hosts."""
    import cairosvg
    return [cairosvg.svg2png(bytestring=_outlined(page)) for page in svg_pages(diagram, monochrome)]


def append_fpdf(pdf, diagrams):
    import cairosvg
    for d in diagrams:
        for svg in svg_pages(d):
            pdf.add_page()
            width = pdf.w - pdf.l_margin - pdf.r_margin
            y = pdf.get_y()
            # The exact shared scene is rasterized with bundled glyph outlines.
            # This avoids FPDF's nested SVG/font limitations and preserves Unicode.
            png = cairosvg.svg2png(bytestring=_outlined(svg), scale=1.5)
            pdf.image(io.BytesIO(png), x=pdf.l_margin, y=y, w=width)
            pdf.set_y(y + width * HEIGHT / WIDTH)


def html_overview(diagrams):
    sections = []
    for d in diagrams:
        svg = render(d, 'svg').decode()
        sections.append('<section class="nc-diagram" style="break-before:page"><h2>' + escape(d['title']) +
                        '</h2><div style="width:100%;overflow:auto">' + svg.replace(f'width="{WIDTH}"', 'width="100%"', 1) +
                        '</div><p>' + escape(d['notice']) + '</p></section>')
    return ''.join(sections)
