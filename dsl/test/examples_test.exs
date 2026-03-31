defmodule ErlkoenigNft.ExamplesTest do
  use ExUnit.Case

  @examples_dir Path.expand("../../examples", __DIR__)

  # Examples that need external runtime dependencies (e.g. cgroup lookups)
  # and cannot be compiled in a test environment.
  @skip_files MapSet.new(["service_mesh.exs"])

  # Compile all examples once at module load time.
  # Each file defines unique Firewall.*, Guard.*, Watch.* modules.
  @example_files Path.wildcard(Path.join(@examples_dir, "*.exs"))
                 |> Enum.reject(&(Path.basename(&1) in @skip_files))
                 |> Enum.sort()

  @compiled (
    for file <- @example_files do
      modules = Code.compile_file(file) |> Enum.map(&elem(&1, 0))
      {Path.basename(file), modules}
    end
  )

  for {file, modules} <- @compiled do
    fw_mods = Enum.filter(modules, &String.starts_with?(Atom.to_string(&1), "Elixir.Firewall."))
    guard_mods = Enum.filter(modules, &String.starts_with?(Atom.to_string(&1), "Elixir.Guard."))
    watch_mods = Enum.filter(modules, &String.starts_with?(Atom.to_string(&1), "Elixir.Watch."))

    # --- Firewall modules ---

    for mod <- fw_mods do
      describe "#{file} — #{mod}" do
        test "config() returns a map with :table and :chains" do
          term = unquote(mod).config()
          assert is_map(term), "config() must return a map"
          assert is_binary(term.table), ":table must be a binary"
          assert is_list(term.chains), ":chains must be a list"
          assert length(term.chains) > 0, "must have at least one chain"
        end

        test "every chain has :name and :rules" do
          term = unquote(mod).config()

          for chain <- term.chains do
            assert is_binary(chain.name) or is_list(chain.name),
                   "chain name must be string: #{inspect(chain)}"

            assert is_list(chain.rules),
                   "chain rules must be list: #{inspect(chain.name)}"
          end
        end

        test "base chains have :hook, :policy; regular chains do not" do
          term = unquote(mod).config()

          for chain <- term.chains do
            case Map.get(chain, :hook) do
              nil ->
                # Regular chain — must not have hook/type/priority/policy
                refute Map.has_key?(chain, :policy),
                       "regular chain #{chain.name} should not have :policy"

              hook ->
                assert hook in [:input, :output, :forward, :prerouting, :postrouting, :ingress],
                       "invalid hook #{inspect(hook)} in chain #{chain.name}"

                assert Map.has_key?(chain, :policy),
                       "base chain #{chain.name} must have :policy"
            end
          end
        end

        test "write! produces a file that file:consult can read back" do
          path = Path.join(System.tmp_dir!(), "example_#{unquote(file)}_#{:rand.uniform(100_000)}.term")

          try do
            unquote(mod).write!(path)
            assert File.exists?(path)

            {:ok, [read_back]} = :file.consult(String.to_charlist(path))
            assert is_map(read_back)
            assert Map.has_key?(read_back, :table)
            assert Map.has_key?(read_back, :chains)
          after
            File.rm(path)
          end
        end

        test "no duplicate chain names" do
          term = unquote(mod).config()
          names = Enum.map(term.chains, & &1.name)
          dupes = names -- Enum.uniq(names)
          assert dupes == [], "duplicate chain names: #{inspect(Enum.uniq(dupes))}"
        end

        test "zone dispatch chains (if present) have correct structure" do
          term = unquote(mod).config()
          dispatch = Enum.find(term.chains, &(&1.name == "z_dispatch_input"))

          if dispatch do
            assert dispatch.hook == :input
            assert dispatch.policy == :drop
            assert :ct_established_accept in dispatch.rules
            assert {:iifname_accept, "lo"} in dispatch.rules
          end
        end
      end
    end

    # --- Guard modules ---

    for mod <- guard_mods do
      test "#{file} — #{mod}.guard_config() returns valid config" do
        gc = unquote(mod).guard_config()
        assert is_map(gc), "guard_config() must return a map"
        assert is_integer(gc.ban_duration), ":ban_duration must be integer"
        assert is_list(gc.whitelist), ":whitelist must be a list"
      end
    end

    # --- Watch modules ---

    for mod <- watch_mods do
      test "#{file} — #{mod}.watches() returns valid config" do
        watches = unquote(mod).watches()
        assert is_list(watches), "watches() must return a list"

        for w <- watches do
          assert is_map(w), "each watch must be a map"
          assert Map.has_key?(w, :interval), "watch must have :interval"
          assert Map.has_key?(w, :thresholds), "watch must have :thresholds"
        end
      end
    end
  end
end
