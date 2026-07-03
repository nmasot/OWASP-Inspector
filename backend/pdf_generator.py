from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from datetime import datetime
import io
import re

def generar_reporte_pdf(target: str, mode: str, resultados: list, plan_ia: str, auditor: str) -> bytes:
    """
    Genera un reporte PDF profesional con anchos fijos para evitar desbordamientos
    y un formateador especial para la Inteligencia Artificial.
    """
    buffer = io.BytesIO()
    
    # El ancho total de A4 es 21cm. Con márgenes de 1.5cm, nos quedan 18cm usables.
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=1.5*cm, leftMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm, title="OWASP Inspector Report"
    )
    
    styles = getSampleStyleSheet()
    
    # Diccionario de Estilos Personalizados
    style_title = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#0891b2'), spaceAfter=6, fontName='Helvetica-Bold', alignment=TA_CENTER)
    style_subtitle = ParagraphStyle('CustomSub', parent=styles['Normal'], fontSize=12, textColor=colors.HexColor('#64748b'), spaceAfter=20, alignment=TA_CENTER)
    style_heading2 = ParagraphStyle('CustomHeading2', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#1e293b'), spaceAfter=12, fontName='Helvetica-Bold')
    style_normal = ParagraphStyle('CustomNormal', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#334155'), spaceAfter=8, alignment=TA_JUSTIFY, leading=14)
    style_table_header = ParagraphStyle('TableHeader', parent=styles['Normal'], fontSize=9, textColor=colors.white, fontName='Helvetica-Bold', alignment=TA_CENTER)
    
    # ESTE ES EL ESTILO QUE EVITA EL DESBORDAMIENTO: Permite el salto de línea automático dentro de la celda
    style_table_cell = ParagraphStyle('TableCell', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#1e293b'), leading=11, alignment=TA_LEFT)
    
    elements = []
    
    # 1. Portada y Encabezado
    elements.append(Paragraph("OWASP Inspector", style_title))
    elements.append(Paragraph(f"Reporte de Auditoría de Seguridad<br/>Objetivo: <b>{target}</b>", style_subtitle))
    elements.append(Spacer(1, 0.5*cm))
    
    elements.append(Paragraph(f"<b>Auditor a cargo:</b> {auditor}", style_normal))
    elements.append(Paragraph(f"<b>Fecha de Escaneo:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style_normal))
    elements.append(Paragraph(f"<b>Modo de Ejecución:</b> {mode.upper()}", style_normal))
    elements.append(Spacer(1, 1*cm))
    
    # 2. Sección de Resultados (Tabla Unificada)
    elements.append(Paragraph("📊 Hallazgos de Vulnerabilidades", style_heading2))
    
    # Encabezados de la tabla
    table_data = [[
        Paragraph("ID", style_table_header), 
        Paragraph("Categoría", style_table_header), 
        Paragraph("Sev", style_table_header), 
        Paragraph("Evidencia", style_table_header), 
        Paragraph("Mitigación", style_table_header)
    ]]
    
    # Filtrar y agregar solo lo vulnerable a la tabla para mantener la limpieza visual
    vulnerables = [r for r in resultados if r.get("status") == "VULNERABLE"]
    
    for r in vulnerables:
        sev = r.get("severity", "INFO")
        if sev == "CRITICAL": color_sev = '<font color="#ef4444"><b>CRIT</b></font>'
        elif sev == "HIGH": color_sev = '<font color="#f97316"><b>HIGH</b></font>'
        else: color_sev = '<font color="#f59e0b"><b>MED</b></font>'
        
        table_data.append([
            Paragraph(r.get("id", "").split('-')[0], style_table_cell),
            Paragraph(r.get("name", ""), style_table_cell),
            Paragraph(color_sev, style_table_cell),
            # Al envolver los textos en Paragraph(), ReportLab los ajusta automáticamente al ancho de la columna
            Paragraph(str(r.get("details", "")), style_table_cell),
            Paragraph(str(r.get("remediation", "")), style_table_cell)
        ])
    
    if len(table_data) > 1:
        # ASIGNACIÓN ESTRICTA DE ANCHOS (Total exacto: 18 cm)
        col_widths = [1.2*cm, 3.8*cm, 1.2*cm, 5.9*cm, 5.9*cm]
        
        vuln_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')), # Fondo cabecera
            ('VALIGN', (0, 0), (-1, -1), 'TOP'), # Alinear texto arriba
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')), # Bordes grises
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(vuln_table)
    else:
        elements.append(Paragraph("¡Excelente! No se encontraron vulnerabilidades en las pruebas realizadas.", style_normal))
        
    elements.append(Spacer(1, 1*cm))
    
    # 3. Plan de Mitigación IA (Renderizado Especial)
    if plan_ia and plan_ia.strip():
        elements.append(PageBreak())
        elements.append(Paragraph("🤖 Plan de Remediación Inteligente", style_heading2))
        
        # Procesador Markdown a PDF
        elementos_ia = _renderizar_markdown_ia(plan_ia, styles)
        elements.extend(elementos_ia)
    
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

def _renderizar_markdown_ia(plan: str, styles) -> list:
    """
    Convierte el formato Markdown devuelto por Gemini en objetos Paragraph de ReportLab
    para una lectura profesional, formateando viñetas, negritas y bloques de código.
    """
    elements = []
    
    # Estilos específicos para la IA
    st_normal = ParagraphStyle('IA_Norm', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#334155'), spaceAfter=8, leading=14)
    st_h3 = ParagraphStyle('IA_H3', parent=styles['Heading3'], fontSize=12, textColor=colors.HexColor('#0891b2'), spaceBefore=12, spaceAfter=6)
    st_bullet = ParagraphStyle('IA_Bull', parent=st_normal, leftIndent=15, firstLineIndent=-10)
    
    # Estilo de consola/código
    st_code = ParagraphStyle('IA_Code', parent=styles['Normal'], fontName='Courier', fontSize=8.5, textColor=colors.HexColor('#e2e8f0'), backColor=colors.HexColor('#1e293b'), leftIndent=10, rightIndent=10, spaceBefore=5, spaceAfter=10, borderPadding=6)

    # 1. Limpiar firma de la IA
    plan = re.sub(r'\[Generado dinámicamente por .*?\]\n*', '', plan)
    
    # 2. Traducir negritas de Markdown (**texto**) a etiquetas HTML que ReportLab entiende (<b>texto</b>)
    plan = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', plan)
    
    lines = plan.split('\n')
    in_code_block = False
    code_lines = []

    for line in lines:
        line = line.strip()
        
        # Manejo de bloques de código (```bash, ```python, etc.)
        if line.startswith('```'):
            if in_code_block:
                code_text = "<br/>".join(code_lines)
                elements.append(Paragraph(code_text, st_code))
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
            continue

        if in_code_block:
            # Reemplazar espacios y caracteres XML sensibles dentro del código
            safe_line = line.replace(' ', '&nbsp;').replace('<', '&lt;').replace('>', '&gt;')
            code_lines.append(safe_line)
            continue

        if not line:
            continue

        # Procesamiento jerárquico del texto
        if line.startswith('### ') or line.startswith('## ') or line.startswith('# '):
            clean_title = line.lstrip('#').strip()
            elements.append(Paragraph(f"<b>{clean_title}</b>", st_h3))
            
        elif line.startswith('- ') or line.startswith('* '):
            clean_bullet = line[2:].strip()
            elements.append(Paragraph(f"• {clean_bullet}", st_bullet))
            
        else:
            elements.append(Paragraph(line, st_normal))

    return elements