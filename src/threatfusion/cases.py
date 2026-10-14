import asyncio
from uuid import uuid4

from .case_models import AuditEntry, EnrichmentJob
from .demo import demo_providers
from .extraction import extract_case
from .models import IOCType, utcnow
from .service import Fusion
from .triage import prioritize


class Cases:
    """Case updates are atomic so enrichment cannot erase concurrent analyst notes."""

    def __init__(self, fusion):
        self.fusion = fusion
        self.store = fusion.store
        self.demo = Fusion(
            fusion.settings.model_copy(update={"demo": True}), providers=demo_providers()
        )
        self.tasks = {}
        self.active_cases = set()
        self.lock = asyncio.Lock()
        self.slots = asyncio.Semaphore(2)
        self.store.recover_jobs()

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def create(self, title, source_name, text, synthetic=False):
        case = await asyncio.to_thread(extract_case, title, source_name, text, synthetic)
        prioritize(case)
        await asyncio.to_thread(self.store.save_case, case)
        return case

    async def get(self, identifier):
        case = await asyncio.to_thread(self.store.get_case, identifier)
        if not case:
            raise KeyError("Case not found")
        return case

    async def review(self, case_id, indicator_id, disposition, note):
        def update(case):
            item = next((i for i in case.indicators if i.id == indicator_id), None)
            if not item:
                raise KeyError("Indicator not found")
            item.disposition, item.note = disposition, note
            case.updated_at = utcnow()
            case.audit.append(
                AuditEntry(action="review", detail=f"{item.ioc.value}: {disposition}")
            )
            case.audit = case.audit[-500:]

        return await asyncio.to_thread(self.store.update_case, case_id, update)

    async def start(self, case_id, mode="demo", selected=None, allow_url=False):
        case = await self.get(case_id)
        if mode == "live" and not selected:
            raise ValueError("Select at least one indicator explicitly before live enrichment")
        if mode == "live" and (case.synthetic or self.fusion.settings.demo):
            raise ValueError(
                "Live enrichment requires a real imported case and live server configuration"
            )
        if selected and not set(selected).issubset({i.id for i in case.indicators}):
            raise ValueError("Selected indicator does not belong to this case")
        candidates = [i for i in case.indicators if not selected or i.id in selected]
        allowed = [
            i
            for i in candidates
            if mode == "demo" or (i.ioc.public and (i.ioc.type != IOCType.url or allow_url))
        ]
        async with self.lock:
            if case_id in self.active_cases:
                raise ValueError("This case already has an active enrichment job")
            if len(self.active_cases) >= 4:
                raise ValueError("Enrichment queue full; wait for an active job")
            job = EnrichmentJob(
                id=str(uuid4()),
                case_id=case_id,
                mode=mode,
                total=len(allowed),
                skipped=len(candidates) - len(allowed),
            )
            await asyncio.to_thread(self.store.save_job, job)
            self.active_cases.add(case_id)
            self.tasks[job.id] = asyncio.create_task(self._run(job, allowed, allow_url))
        return job

    async def _run(self, job, indicators, allow_url):
        def audit(case, action, detail):
            case.updated_at = utcnow()
            case.audit.append(AuditEntry(action=action, detail=detail))
            case.audit = case.audit[-500:]

        try:
            async with self.slots:
                job.status = "running"
                await asyncio.to_thread(self.store.save_job, job)
                await asyncio.to_thread(
                    self.store.update_case,
                    job.case_id,
                    lambda c: audit(
                        c,
                        "enrichment started",
                        f"{job.mode}; {job.total} selected; {job.skipped} privacy skips; full URL consent: {allow_url}",
                    ),
                )
                fusion = self.demo if job.mode == "demo" else self.fusion
                for indicator in indicators:
                    result = await fusion.analyze(indicator.ioc.value, allow_url=allow_url)

                    def update(case, result=result, item_id=indicator.id):
                        item = next(i for i in case.indicators if i.id == item_id)
                        item.analysis = result
                        case.updated_at = utcnow()
                        prioritize(case)

                    await asyncio.to_thread(self.store.update_case, job.case_id, update)
                    job.completed += 1
                    job.updated_at = utcnow()
                    await asyncio.to_thread(self.store.save_job, job)
                job.status = "completed"
                job.message = (
                    "Lookups complete; provider errors and gaps remain visible per indicator"
                )
        except asyncio.CancelledError:
            job.status = "cancelled"
            job.message = (
                "Cancelled; completed evidence retained. A request already sent cannot be recalled."
            )
        except Exception:
            job.status = "failed"
            job.message = "Job interrupted by an internal error; completed evidence retained"
        finally:
            job.updated_at = utcnow()
            await asyncio.to_thread(self.store.save_job, job)
            try:
                await asyncio.to_thread(
                    self.store.update_case,
                    job.case_id,
                    lambda c: audit(
                        c,
                        "enrichment " + job.status,
                        f"{job.completed}/{job.total} lookups completed",
                    ),
                )
            except KeyError:
                pass
            self.active_cases.discard(job.case_id)
            self.tasks.pop(job.id, None)

    async def cancel(self, job_id):
        job = await asyncio.to_thread(self.store.get_job, job_id)
        if not job:
            raise KeyError("Job not found")
        task = self.tasks.get(job_id)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            current = await asyncio.to_thread(self.store.get_job, job_id)
            if current and current.status in ("queued", "running"):
                current.status = "cancelled"
                current.message = "Cancelled before processing started"
                current.updated_at = utcnow()
                await asyncio.to_thread(self.store.save_job, current)
                self.active_cases.discard(job.case_id)
                self.tasks.pop(job_id, None)
        return await asyncio.to_thread(self.store.get_job, job_id)

    async def delete(self, case_id):
        await self.get(case_id)
        if case_id in self.active_cases:
            raise ValueError("Cancel the active enrichment job before deleting this case")
        await asyncio.to_thread(self.store.delete_case, case_id)
