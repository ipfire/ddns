<?xml version='1.0'?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl"/>

<!-- translate man page references to links to html pages -->
<xsl:template match="citerefentry">
  <a>
    <xsl:attribute name="href">
      <xsl:value-of select="refentrytitle"/><xsl:text>.html</xsl:text>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<!-- add Index link at top of page -->
<xsl:template name="user.header.content">
  <a>
    <xsl:attribute name="href">
      <xsl:text>index.html</xsl:text>
    </xsl:attribute>
    <xsl:text>Index</xsl:text>
  </a>
  <hr/>
</xsl:template>

<!-- Switch things to UTF-8, ISO-8859-1 is soo yesteryear -->
<xsl:output method="html" encoding="UTF-8" indent="no"/>

</xsl:stylesheet>
