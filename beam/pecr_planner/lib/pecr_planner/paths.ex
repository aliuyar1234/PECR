defmodule PecrPlanner.Paths do
  @moduledoc false

  @beam_root Path.expand(Path.join([__DIR__, "..", ".."]))
  @repo_root Path.expand(Path.join([__DIR__, "..", "..", "..", ".."]))

  @spec beam_root() :: String.t()
  def beam_root, do: @beam_root

  @spec repo_root() :: String.t()
  def repo_root, do: @repo_root

  @spec resolve_repo_path(String.t() | nil, String.t() | nil) ::
          {:ok, String.t()} | {:error, String.t()}
  def resolve_repo_path(path, default_relative_path \\ nil)

  def resolve_repo_path(nil, nil), do: {:error, "path is required"}

  def resolve_repo_path(nil, default_relative_path) when is_binary(default_relative_path) do
    resolve_repo_path(default_relative_path, nil)
  end

  def resolve_repo_path(path, _default_relative_path) when is_binary(path) do
    expanded =
      path
      |> String.replace("\\", "/")
      |> Path.expand(@repo_root)

    if within_root?(expanded, @repo_root) do
      {:ok, expanded}
    else
      {:error, "path must stay within the repository root"}
    end
  end

  defp within_root?(path, root) do
    normalized_path = normalize(path)
    normalized_root = normalize(root)

    normalized_path == normalized_root or
      String.starts_with?(normalized_path, normalized_root <> "/")
  end

  defp normalize(path) do
    path
    |> String.replace("\\", "/")
    |> String.downcase()
  end
end
