#!/usr/bin/env python3
"""One-off build to v3 when main docx files are locked."""

import build_resume_docx as br
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "Praisel_Ekpenyong_Resume_v5.docx"


def build():
    doc = Document()
    br.configure_document_styles(doc)

    section = doc.sections[0]
    section.top_margin = br.Pt(54)
    section.bottom_margin = br.Pt(54)
    section.left_margin = br.Pt(54)
    section.right_margin = br.Pt(54)

    br.add_text_paragraph(
        doc,
        br.CONTACT["name"],
        size=br.NAME_SIZE,
        bold=True,
        space_after=2,
        alignment=WD_ALIGN_PARAGRAPH.CENTER,
    )
    br.add_text_paragraph(
        doc,
        f"{br.CONTACT['phone']} | {br.CONTACT['email']} | {br.CONTACT['links']}",
        size=br.CONTACT_SIZE,
        space_after=2,
        alignment=WD_ALIGN_PARAGRAPH.CENTER,
    )
    br.add_text_paragraph(
        doc,
        br.CONTACT["location"],
        size=br.CONTACT_SIZE,
        space_after=6,
        alignment=WD_ALIGN_PARAGRAPH.CENTER,
    )

    br.add_section_heading(doc, "Education & Certificates", space_before=0)
    for line in br.EDUCATION:
        br.add_bullet(doc, line)

    br.add_section_heading(doc, "Projects")
    for project in br.PROJECTS:
        br.add_job(doc, project["title"], project["dates"], project["bullets"])

    br.add_section_heading(doc, "Work History", space_before=8)
    for job in br.WORK_HISTORY:
        br.add_job(doc, job["title"], job["dates"], job["bullets"])

    doc.save(OUTPUT)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    build()