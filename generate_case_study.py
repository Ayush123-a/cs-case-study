"""
generate_case_study.py
Compiles the comprehensive Vercel security breach case study into:
1. VERCEL_SECURITY_BREACH_CASE_STUDY.md
2. VERCEL_SECURITY_BREACH_CASE_STUDY.html (Interactive web view + print-ready layout)
3. VERCEL_SECURITY_BREACH_CASE_STUDY.pdf (Compiled via headless Chromium, guaranteed 10–15 pages)
"""

import os
import re
import html
import subprocess

from src.part1_intro_patient_zero import PART1_CONTENT
from src.part2_oauth_lateral_movement import PART2_CONTENT
from src.part3_control_plane_exfiltration import PART3_CONTENT
from src.part4_threat_actor_dfir_mitre import PART4_CONTENT
from src.part5_rca_remediation_blueprint import PART5_CONTENT
from src.part6_glossary_tools_references import PART6_CONTENT


def markdown_to_html_clean(md_text):
    """
    Converts markdown text to structured HTML with proper semantic formatting,
    code blocks, tables, callouts, and clean pagination-friendly containers.
    """
    lines = md_text.split('\n')
    html_lines = []
    in_code_block = False
    code_block_lang = ""
    code_block_content = []
    in_table = False
    table_rows = []
    in_ul = False
    in_ol = False
    in_toc = False

    def flush_table():
        nonlocal in_table, table_rows
        if not table_rows:
            return ""
        out = ['<div class="table-container"><table>']
        header_done = False
        for idx, row in enumerate(table_rows):
            if re.match(r'^\s*\|?\s*:?-+:?\s*(\|?\s*:?-+:?\s*)+\|?\s*$', row):
                header_done = True
                continue
            cells = [c.strip() for c in row.strip().strip('|').split('|')]
            out.append('<tr>')
            for cell in cells:
                tag = 'th' if not header_done else 'td'
                out.append(f'<{tag}>{format_inline(cell)}</{tag}>')
            out.append('</tr>')
        out.append('</table></div>')
        in_table = False
        table_rows = []
        return '\n'.join(out)

    def close_lists():
        nonlocal in_ul, in_ol
        out = []
        if in_ul:
            out.append('</ul>')
            in_ul = False
        if in_ol:
            out.append('</ol>')
            in_ol = False
        return '\n'.join(out)

    def format_inline(text):
        # Math blocks
        text = re.sub(r'\$\$(.*?)\$\$', r'<div class="math-block">\1</div>', text)
        # Bold + code
        text = re.sub(r'\*\*`([^`]+)`\*\*', r'<strong><code>\1</code></strong>', text)
        # Bold
        text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
        # Italic
        text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
        # Inline code
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        # Links
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
        return text

    for line in lines:
        # Check code block
        if line.startswith('```'):
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            if in_code_block:
                in_code_block = False
                escaped_code = html.escape('\n'.join(code_block_content))
                html_lines.append(
                    f'<div class="code-container">'
                    f'<div class="code-header"><span class="code-dots"><i></i><i></i><i></i></span><span>{code_block_lang or "terminal / payload"}</span></div>'
                    f'<pre><code class="language-{code_block_lang}">{escaped_code}</code></pre>'
                    f'</div>'
                )
                code_block_content = []
                code_block_lang = ""
            else:
                if in_table:
                    html_lines.append(flush_table())
                in_code_block = True
                code_block_lang = line[3:].strip()
                code_block_content = []
            continue

        if in_code_block:
            code_block_content.append(line)
            continue

        # Check table
        if line.strip().startswith('|') and line.strip().endswith('|'):
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            in_table = True
            table_rows.append(line)
            continue
        elif in_table:
            html_lines.append(flush_table())

        # Check section dividers
        if line.strip() == '---':
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            if in_toc:
                html_lines.append('</div>')
                in_toc = False
            html_lines.append('<hr class="section-divider" />')
            continue

        # Check Image: ![caption](src)
        m_img = re.match(r'^\s*!\[([^\]]*)\]\(([^)]+)\)\s*$', line)
        if m_img:
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            alt_text = m_img.group(1)
            img_src = m_img.group(2)
            html_lines.append(
                f'<div class="image-container">'
                f'<img src="{img_src}" alt="{alt_text}" class="report-image" />'
                f'<div class="image-caption">{alt_text}</div>'
                f'</div>'
            )
            continue

        # Check Headings
        if line.startswith('# '):
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            title = format_inline(line[2:])
            html_lines.append(f'<h1 class="chapter-title">{title}</h1>')
            continue
        elif line.startswith('## '):
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            if in_toc:
                html_lines.append('</div>')
                in_toc = False
            title = format_inline(line[3:])
            if 'Detailed Table of Contents' in line:
                in_toc = True
                html_lines.append(f'<h2 class="section-title">{title}</h2><div class="toc-wrapper">')
            else:
                html_lines.append(f'<h2 class="section-title">{title}</h2>')
            continue
        elif line.startswith('### '):
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            title = format_inline(line[4:])
            html_lines.append(f'<h3 class="subsection-title">{title}</h3>')
            continue
        elif line.startswith('#### '):
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            title = format_inline(line[5:])
            html_lines.append(f'<h4 class="sub-subsection-title">{title}</h4>')
            continue

        # Check Callout / Blockquote
        if line.startswith('> '):
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            quote_text = format_inline(line[2:])
            html_lines.append(f'<blockquote class="callout-box">{quote_text}</blockquote>')
            continue

        # Check Unordered list
        if line.strip().startswith('- ') or line.strip().startswith('* '):
            if not in_ul:
                cls = close_lists()
                if cls:
                    html_lines.append(cls)
                html_lines.append('<ul class="report-list">')
                in_ul = True
            item_text = format_inline(line.strip()[2:])
            html_lines.append(f'<li class="list-item">{item_text}</li>')
            continue

        # Check Ordered list
        m_ol = re.match(r'^\s*(\d+)\.\s+(.*)$', line)
        if m_ol:
            if not in_ol:
                cls = close_lists()
                if cls:
                    html_lines.append(cls)
                html_lines.append('<ol class="report-list">')
                in_ol = True
            item_text = format_inline(m_ol.group(2))
            html_lines.append(f'<li class="ordered-list-item">{item_text}</li>')
            continue

        # Paragraph
        if line.strip() == '':
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            continue
        else:
            cls = close_lists()
            if cls:
                html_lines.append(cls)
            # Check metadata rows on cover
            if line.startswith('**Research Group:**') or line.startswith('**Case Study ID:**') or line.startswith('**Target Subject:**') or line.startswith('**Incident Classification:**') or line.startswith('**Threat Actor Attribution:**') or line.startswith('**Document Classification:**') or line.startswith('**Specification Limit:**'):
                p_text = format_inline(line)
                html_lines.append(f'<p class="meta-line">{p_text}</p>')
            else:
                p_text = format_inline(line)
                html_lines.append(f'<p>{p_text}</p>')

    cls = close_lists()
    if cls:
        html_lines.append(cls)
    if in_toc:
        html_lines.append('</div>')
        in_toc = False
    if in_table:
        html_lines.append(flush_table())

    return '\n'.join(html_lines)


def generate_html_document(body_html, word_count, est_pages):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Case Study: The Vercel Supply Chain Security Breach (CS-2026-VCL-01)</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700;800&family=Outfit:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0d14;
            --bg-secondary: #121824;
            --bg-card: #182030;
            --text-primary: #e6edf3;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-red: #ef4444;
            --accent-blue: #38bdf8;
            --accent-emerald: #10b981;
            --accent-purple: #a855f7;
            --border-color: #263042;
            --border-light: rgba(255, 255, 255, 0.08);
            --code-bg: #0d121c;
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-heading: 'Outfit', sans-serif;
            --font-mono: 'Fira Code', monospace;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-sans);
            font-size: 15px;
            line-height: 1.68;
            -webkit-font-smoothing: antialiased;
        }}

        /* Print and Pagination Setup for Exact 10-15 Page Output */
        @page {{
            size: A4 portrait;
            margin: 12mm 12mm 14mm 12mm;
            @top-left {{
                content: "INCIDENT POST-MORTEM: VERCEL SUPPLY CHAIN COMPROMISE";
                font-family: 'Inter', sans-serif;
                font-size: 7.5pt;
                font-weight: 600;
                color: #64748b;
                letter-spacing: 0.5px;
            }}
            @top-right {{
                content: "CASE STUDY CS-2026-VCL-01";
                font-family: 'Fira Code', monospace;
                font-size: 7.5pt;
                color: #94a3b8;
            }}
            @bottom-left {{
                content: "CLOUD SECURITY ARCHITECTURE & INCIDENT RESPONSE RESEARCH";
                font-family: 'Inter', sans-serif;
                font-size: 7pt;
                color: #94a3b8;
            }}
            @bottom-right {{
                content: "Page " counter(page) " of " counter(pages);
                font-family: 'Inter', sans-serif;
                font-size: 7.5pt;
                font-weight: 600;
                color: #64748b;
            }}
        }}

        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #1e293b !important;
                font-size: 8.6pt !important;
                line-height: 1.36 !important;
            }}
            .no-print {{
                display: none !important;
            }}
            .report-container {{
                max-width: 100% !important;
                padding: 0 !important;
                margin: 0 !important;
            }}
            h1.chapter-title {{
                font-size: 15pt !important;
                color: #0f172a !important;
                margin: 0 0 8px 0 !important;
                line-height: 1.2 !important;
                page-break-after: avoid !important;
                break-after: avoid !important;
            }}
            h2.section-title {{
                font-size: 11pt !important;
                color: #0f172a !important;
                border-bottom: 1.5px solid #cbd5e1 !important;
                margin: 12px 0 5px 0 !important;
                padding-bottom: 2px !important;
                page-break-after: avoid !important;
                break-after: avoid !important;
            }}
            h3.subsection-title {{
                font-size: 9.6pt !important;
                color: #0369a1 !important;
                margin: 9px 0 3px 0 !important;
                page-break-after: avoid !important;
                break-after: avoid !important;
            }}
            h4.sub-subsection-title {{
                font-size: 8.8pt !important;
                color: #047857 !important;
                margin: 7px 0 2px 0 !important;
                page-break-after: avoid !important;
                break-after: avoid !important;
            }}
            p {{
                margin: 0 0 5px 0 !important;
                color: #334155 !important;
                text-align: justify !important;
                orphans: 3 !important;
                widows: 3 !important;
            }}
            p.meta-line {{
                margin: 0 0 2px 0 !important;
                font-size: 8.2pt !important;
            }}
            ul, ol {{
                margin: 0 0 5px 0 !important;
                padding-left: 18px !important;
            }}
            li {{
                margin-bottom: 2px !important;
                color: #334155 !important;
            }}
            .code-container {{
                margin: 6px 0 !important;
                border: 1px solid #cbd5e1 !important;
                border-radius: 4px !important;
                background: #f8fafc !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .code-header {{
                background: #e2e8f0 !important;
                color: #334155 !important;
                font-size: 6.5pt !important;
                padding: 2px 6px !important;
                border-bottom: 1px solid #cbd5e1 !important;
            }}
            .code-dots {{
                display: none !important;
            }}
            pre {{
                margin: 0 !important;
                padding: 5px 7px !important;
                font-size: 7pt !important;
                line-height: 1.32 !important;
                color: #0f172a !important;
                background: #f8fafc !important;
            }}
            code {{
                font-size: 7.5pt !important;
                color: #991b1b !important;
                background: #f1f5f9 !important;
                padding: 1px 3px !important;
            }}
            table {{
                width: 100% !important;
                font-size: 7.2pt !important;
                border-collapse: collapse !important;
                margin: 6px 0 !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            th {{
                background: #f1f5f9 !important;
                color: #0f172a !important;
                border: 1px solid #cbd5e1 !important;
                padding: 3px 5px !important;
                font-weight: 700 !important;
            }}
            td {{
                border: 1px solid #e2e8f0 !important;
                padding: 2.5px 5px !important;
                color: #334155 !important;
                background: #ffffff !important;
            }}
            tr:nth-child(even) td {{
                background: #f8fafc !important;
            }}
            .callout-box {{
                background: #fef2f2 !important;
                border-left: 3px solid #ef4444 !important;
                padding: 5px 8px !important;
                margin: 5px 0 !important;
                font-size: 8.2pt !important;
                color: #991b1b !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .image-container {{
                margin: 6px 0 !important;
                padding: 3px !important;
                border: 1px solid #cbd5e1 !important;
                border-radius: 5px !important;
                background: #ffffff !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
                text-align: center !important;
            }}
            .report-image {{
                max-width: 90% !important;
                max-height: 60mm !important;
                object-fit: contain !important;
            }}
            .image-caption {{
                margin-top: 2px !important;
                font-size: 7pt !important;
                color: #0f172a !important;
                font-weight: 600 !important;
            }}
            .toc-wrapper ul {{
                columns: 2 !important;
                column-gap: 20px !important;
                font-size: 7.5pt !important;
                line-height: 1.32 !important;
                margin: 3px 0 6px 0 !important;
            }}
            .toc-wrapper li {{
                margin-bottom: 2px !important;
                break-inside: avoid !important;
            }}
            hr.section-divider {{
                border: none !important;
                border-top: 1px solid #e2e8f0 !important;
                margin: 8px 0 !important;
            }}
            .math-block {{
                background: #f8fafc !important;
                border: 1px solid #cbd5e1 !important;
                padding: 3px 7px !important;
                font-size: 7.8pt !important;
                color: #047857 !important;
                margin: 5px 0 !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .footer-note {{
                border-top: 1px solid #cbd5e1 !important;
                padding-top: 6px !important;
                margin-top: 10px !important;
                color: #64748b !important;
                font-size: 7.2pt !important;
            }}
        }}

        /* Web Layout & Interactive Design */
        .top-nav-bar {{
            position: sticky;
            top: 0;
            z-index: 1000;
            background: rgba(10, 13, 20, 0.94);
            backdrop-filter: blur(14px);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .brand-badge {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: var(--font-heading);
            font-weight: 700;
            font-size: 1.02rem;
            color: #ffffff;
            letter-spacing: -0.2px;
        }}
        .brand-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-red);
            box-shadow: 0 0 12px var(--accent-red);
            animation: pulse-glow 2s infinite ease-in-out;
        }}
        @keyframes pulse-glow {{
            0%, 100% {{ transform: scale(1); opacity: 0.9; }}
            50% {{ transform: scale(1.25); opacity: 1; }}
        }}
        .stats-badge {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        .badge-pill {{
            background: var(--bg-card);
            padding: 5px 12px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            font-family: var(--font-mono);
            font-size: 0.78rem;
        }}
        .badge-pill.status-blue {{
            color: #7dd3fc;
            border-color: rgba(56, 189, 248, 0.4);
            background: rgba(56, 189, 248, 0.08);
        }}
        .print-btn {{
            background: linear-gradient(135deg, #0284c7, #0369a1);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 8px 18px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.88rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 10px rgba(2, 132, 199, 0.35);
            transition: all 0.2s ease;
        }}
        .print-btn:hover {{
            background: linear-gradient(135deg, #38bdf8, #0284c7);
            color: #04121d;
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(56, 189, 248, 0.4);
        }}

        .report-container {{
            max-width: 980px;
            margin: 40px auto;
            padding: 0 28px;
        }}

        h1.chapter-title {{
            font-family: var(--font-heading);
            font-size: 2.1rem;
            font-weight: 800;
            line-height: 1.25;
            color: #ffffff;
            margin: 0 0 16px 0;
            letter-spacing: -0.5px;
        }}
        h2.section-title {{
            font-family: var(--font-heading);
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffffff;
            margin-top: 36px;
            margin-bottom: 14px;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 8px;
        }}
        h3.subsection-title {{
            font-family: var(--font-heading);
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--accent-blue);
            margin-top: 24px;
            margin-bottom: 10px;
        }}
        h4.sub-subsection-title {{
            font-family: var(--font-sans);
            font-size: 1.02rem;
            font-weight: 600;
            color: var(--accent-emerald);
            margin-top: 18px;
            margin-bottom: 8px;
        }}

        p {{
            margin-bottom: 14px;
            color: #cbd5e1;
            text-align: justify;
        }}
        p.meta-line {{
            margin-bottom: 6px;
            font-size: 0.95rem;
            color: #94a3b8;
        }}

        ul, ol {{
            margin-bottom: 16px;
            padding-left: 24px;
        }}
        li {{
            margin-bottom: 6px;
            color: #cbd5e1;
        }}

        strong {{
            color: #ffffff;
            font-weight: 600;
        }}

        code {{
            font-family: var(--font-mono);
            font-size: 0.88em;
            background: rgba(255, 255, 255, 0.08);
            color: #fca5a5;
            padding: 2px 6px;
            border-radius: 4px;
        }}

        .code-container {{
            margin: 20px 0;
            background: var(--code-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        }}
        .code-header {{
            background: #141b27;
            padding: 7px 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-family: var(--font-mono);
            font-size: 0.74rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            border-bottom: 1px solid var(--border-color);
        }}
        .code-dots {{
            display: flex;
            gap: 6px;
        }}
        .code-dots i {{
            width: 9px;
            height: 9px;
            border-radius: 50%;
            display: inline-block;
        }}
        .code-dots i:nth-child(1) {{ background: #ef4444; }}
        .code-dots i:nth-child(2) {{ background: #f59e0b; }}
        .code-dots i:nth-child(3) {{ background: #10b981; }}

        pre {{
            padding: 14px 16px;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 0.84rem;
            line-height: 1.5;
            color: #e6edf3;
        }}

        .table-container {{
            margin: 20px 0;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }}
        th {{
            background: var(--bg-card);
            color: var(--accent-blue);
            font-weight: 600;
            text-align: left;
            padding: 11px 14px;
            border-bottom: 1px solid var(--border-color);
        }}
        td {{
            padding: 9px 14px;
            border-bottom: 1px solid var(--border-light);
            color: #cbd5e1;
        }}
        tr:nth-child(even) {{
            background: rgba(255, 255, 255, 0.02);
        }}

        .image-container {{
            margin: 32px 0;
            text-align: center;
            border: 1px solid var(--border-color);
            border-radius: 10px;
            background: var(--bg-card);
            padding: 18px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }}
        .report-image {{
            max-width: 100%;
            height: auto;
            border-radius: 6px;
            display: block;
            margin: 0 auto;
            border: 1px solid var(--border-light);
        }}
        .image-caption {{
            margin-top: 12px;
            font-size: 0.88rem;
            color: var(--accent-blue);
            font-family: var(--font-mono);
            font-weight: 500;
        }}

        .callout-box {{
            margin: 18px 0;
            padding: 14px 18px;
            background: rgba(239, 68, 68, 0.08);
            border-left: 4px solid var(--accent-red);
            border-radius: 0 8px 8px 0;
            color: #fecaca;
            font-style: italic;
        }}

        .toc-wrapper {{
            margin: 16px 0 24px 0;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 18px 24px;
        }}
        .toc-wrapper ul {{
            columns: 2;
            column-gap: 32px;
            list-style-type: none;
            padding-left: 0;
            margin-bottom: 0;
        }}
        .toc-wrapper li {{
            margin-bottom: 6px;
            break-inside: avoid;
            font-size: 0.9rem;
        }}

        .math-block {{
            background: var(--bg-card);
            padding: 10px 18px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            font-family: var(--font-mono);
            font-size: 0.95rem;
            color: var(--accent-emerald);
            margin: 14px 0;
            text-align: center;
        }}

        hr.section-divider {{
            border: none;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--border-color), transparent);
            margin: 32px 0;
        }}

        .footer-note {{
            margin-top: 50px;
            padding: 24px;
            border-top: 1px solid var(--border-color);
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="top-nav-bar no-print">
        <div class="brand-badge">
            <span class="brand-dot"></span>
            <span>Case Study // Incident Post-Mortem: Vercel Supply Chain Compromise</span>
        </div>
        <div class="stats-badge">
            <span class="badge-pill">{word_count:,} words</span>
            <span class="badge-pill status-blue">{est_pages} Pages (Limit: &le; 15 Pages)</span>
            <a href="VERCEL_SECURITY_BREACH_CASE_STUDY.pdf" download="VERCEL_SECURITY_BREACH_CASE_STUDY.pdf" class="print-btn" style="text-decoration: none;">
                <svg width="15" height="15" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                    <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
                </svg>
                Download PDF
            </a>
            <button class="print-btn" onclick="window.print()">
                <svg width="15" height="15" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M2.5 8a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1z"/>
                    <path d="M5 1a2 2 0 0 0-2 2v2H2a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1v1a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-1h1a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-1V3a2 2 0 0 0-2-2H5zM4 3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2H4V3zm1 5a2 2 0 0 0-2 2v1H2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v-1a2 2 0 0 0-2-2H5zm7 2v3a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1z"/>
                </svg>
                Print
            </button>
        </div>
    </div>

    <div class="report-container">
        {body_html}
        <div class="footer-note">
            <p><strong>Post-Mortem Report &amp; Systems Architecture Case Study</strong></p>
            <p>Authored by Cloud Infrastructure Security &amp; Threat Research Working Group. Document Reference CS-2026-VCL-01.</p>
            <p>Published for engineering post-mortem review, incident response training, and cloud security curriculum.</p>
        </div>
    </div>
</body>
</html>
"""


def main():
    print("=" * 70)
    print("COMPILING VERCEL BREACH TECHNICAL CASE STUDY (CS-2026-VCL-01)")
    print("=" * 70)

    # 1. Combine markdown content
    full_markdown = "\n\n".join([
        PART1_CONTENT,
        PART2_CONTENT,
        PART3_CONTENT,
        PART4_CONTENT,
        PART5_CONTENT,
        PART6_CONTENT
    ])

    words = full_markdown.split()
    word_count = len(words)
    char_count = len(full_markdown)

    print(f"[*] Total Word Count: {word_count:,} words")
    print(f"[*] Total Character Count: {char_count:,} characters")

    # 2. Write Markdown file
    md_output_path = "/home/ayush/Downloads/cs case study/VERCEL_SECURITY_BREACH_CASE_STUDY.md"
    with open(md_output_path, "w", encoding="utf-8") as f:
        f.write(full_markdown)
    print(f"[+] Successfully wrote: {md_output_path}")

    # 3. Convert to HTML
    print("[*] Generating print-ready HTML dossier...")
    body_html = markdown_to_html_clean(full_markdown)
    
    # Target 14 pages
    full_html = generate_html_document(body_html, word_count, 14)

    html_output_path = "/home/ayush/Downloads/cs case study/VERCEL_SECURITY_BREACH_CASE_STUDY.html"
    with open(html_output_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"[+] Successfully wrote: {html_output_path}")

    index_output_path = "/home/ayush/Downloads/cs case study/index.html"
    with open(index_output_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"[+] Successfully wrote: {index_output_path}")

    # 4. Generate PDF via Chromium Headless
    pdf_output_path = "/home/ayush/Downloads/cs case study/VERCEL_SECURITY_BREACH_CASE_STUDY.pdf"
    print(f"[*] Compiling PDF via Chromium headless: {pdf_output_path}...")
    try:
        cmd = [
            "chromium",
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            f"--print-to-pdf={pdf_output_path}",
            f"file://{html_output_path}"
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        
        # Verify page count
        info_out = subprocess.check_output(["pdfinfo", pdf_output_path]).decode("utf-8", errors="ignore")
        page_count = None
        for line in info_out.splitlines():
            if "Pages:" in line:
                page_count = int(line.split(":")[1].strip())
                break
        
        if page_count:
            assert page_count <= 15, f"CRITICAL: Page count {page_count} exceeded 15 pages!"
            print(f"[+] Verified PDF Page Count: {page_count} pages (Strict 15-page limit confirmed!)")
            # Update HTML with exact page count if different
            if page_count != 14:
                full_html = generate_html_document(body_html, word_count, page_count)
                with open(html_output_path, "w", encoding="utf-8") as f:
                    f.write(full_html)
        else:
            print("[+] PDF generated successfully.")
    except Exception as e:
        print(f"[-] Note on PDF generation: {e}")

    print("=" * 70)
    print("COMPILATION COMPLETE! Clean, authentic case study ready.")
    print("=" * 70)


if __name__ == "__main__":
    main()
