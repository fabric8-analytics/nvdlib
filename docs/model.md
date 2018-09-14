    nvdlib.model.Document(
        id_: str,
        cve: nvdlib.model.CVE(
                id_: str,
                year: int,
                assigner: str,
                data_version: str,
                affects: AffectsEntry(data: List[
                ProductNode(
                    vendor_name: str,
                    product_name: str,
                    versions: List[str])]
                )],
                references: ReferenceEntry(data: List[
                ReferenceNode(
                    url: str,
                    refsource: str
                )],
                descriptions: DescriptionEntry(data: List[
                DescriptionNode(
                    lang: str
                )]
        ),
        configurations: nvdlib.model.Configurations(
            cve_data_version: str,
            nodes: List[
                ConfigurationsEntry(
                    data: List[
                        ConfigurationsNode(
                            vulnerable: True,
                            cpe: str
                        )],
                    operator: str
            )]
        ),
        impact: nvdlib.model.Impact(
            severity: str,
            exploitability_score: float,
            impact_score: float,
            cvss: nvdlib.model.Impact.CVSSNode(
                version: str,
                access_vector: str,
                access_complexity: str,
                authentication: str,
                confidentiality_impact: str,
                integrity_impact: str,
                availability_impact: str,
                base_score: float
            )
        ),
        published_date: datetime.datetime(
            year: int,
            month: int,
            day: int,
            hour: int,
            minute: int
        ),
        modified_date: datetime.datetime(
            year: int,
            month: int,
            day: int,
            hour: int,
            minute: int
        )
    )