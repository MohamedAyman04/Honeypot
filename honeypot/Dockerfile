FROM honeynet/conpot:latest

USER conpot

ENV PATH="/home/conpot/.local/bin:${PATH}"

EXPOSE 502

# Use -f (force test config) so conpot uses its built-in default config,
# and point to the bundled default template.
CMD ["conpot", "-f", "--template", "default"]