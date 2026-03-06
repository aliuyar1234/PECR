Application.ensure_all_started(:pecr_planner)
PecrPlanner.JobCLI.main(["nightly-report" | System.argv()])

