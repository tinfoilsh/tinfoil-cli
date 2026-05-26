package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	nbucketCmd.AddCommand(nbucketAccountCmd, nbucketGetCmd, nbucketPutCmd, nbucketDeleteCmd, nbucketMetadataCmd, nbucketRevealCmd, nbucketKeysCmd)
	nbucketAccountCmd.AddCommand(nbucketAccountDeleteCmd)
	nbucketKeysCmd.AddCommand(nbucketKeysAddCmd, nbucketKeysRemoveCmd)

	for _, c := range []*cobra.Command{
		nbucketAccountCmd, nbucketAccountDeleteCmd,
		nbucketGetCmd, nbucketPutCmd, nbucketDeleteCmd,
		nbucketMetadataCmd, nbucketRevealCmd,
		nbucketKeysCmd, nbucketKeysAddCmd, nbucketKeysRemoveCmd,
	} {
		c.SilenceUsage = true
	}

	nbucketGetCmd.Flags().StringP("output", "o", "", "Write to file (default: stdout)")
	nbucketGetCmd.Flags().String("key", "", "User-managed encryption key (base64); required for BYOK items")
	nbucketGetCmd.Flags().String("range", "", "Byte range, e.g. bytes=0-1023")

	nbucketPutCmd.Flags().StringP("file", "f", "", "File to upload (use - for stdin)")
	_ = nbucketPutCmd.MarkFlagRequired("file")
	nbucketPutCmd.Flags().StringArray("key", nil, "User-managed encryption key (base64); may be repeated. If omitted, named-bucket generates and stores one.")
	nbucketPutCmd.Flags().Int64("length", -1, "Plaintext length in bytes (required when --file is -)")

	nbucketKeysAddCmd.Flags().String("new-key", "", "New encryption key to add (base64 32 bytes)")
	_ = nbucketKeysAddCmd.MarkFlagRequired("new-key")
	nbucketKeysAddCmd.Flags().String("proof-key", "", "BYOK proof key (base64); required if the item has no server-managed key")

	nbucketKeysRemoveCmd.Flags().String("remove-key", "", "Encryption key slot to remove (base64 32 bytes)")
	_ = nbucketKeysRemoveCmd.MarkFlagRequired("remove-key")
	nbucketKeysRemoveCmd.Flags().String("proof-key", "", "Proof key (base64); required for BYOK items or when removing the managed key")
	nbucketKeysRemoveCmd.Flags().Bool("unmanage", false, "Acknowledge that removing the managed key drops named-bucket's ability to recover the item without a user-managed key")
}

var nbucketAccountCmd = &cobra.Command{
	Use:   "account",
	Short: "Show whether your named-bucket account exists",
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		resp, err := nbucketDo(nb, apiKey, master, "GET", "/account", nil, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nbucketStatusError(resp)
		}
		var body struct {
			Exists bool `json:"exists"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return fmt.Errorf("decoding /account: %w", err)
		}
		if body.Exists {
			fmt.Println("exists")
		} else {
			fmt.Println("not initialized")
		}
		return nil
	},
}

var nbucketAccountDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete your named-bucket account (must be empty)",
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		resp, err := nbucketDo(nb, apiKey, master, "DELETE", "/account", nil, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusNoContent:
			fmt.Println("account deleted")
			return nil
		case http.StatusBadRequest:
			return fmt.Errorf("account has items — delete them first")
		default:
			return nbucketStatusError(resp)
		}
	},
}

var nbucketGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Fetch a named item",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		out, _ := cmd.Flags().GetString("output")
		key, _ := cmd.Flags().GetString("key")
		rng, _ := cmd.Flags().GetString("range")

		headers := map[string]string{}
		if key != "" {
			headers["X-Encryption-Key"] = key
		}
		if rng != "" {
			headers["Range"] = rng
		}

		resp, err := nbucketDo(nb, apiKey, master, "GET", "/get/"+args[0], headers, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			return nbucketStatusError(resp)
		}

		w := os.Stdout
		if out != "" && out != "-" {
			f, err := os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		if _, err := io.Copy(w, resp.Body); err != nil {
			return fmt.Errorf("streaming body: %w", err)
		}
		return nil
	},
}

var nbucketPutCmd = &cobra.Command{
	Use:   "put <name>",
	Short: "Store a named item",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		filePath, _ := cmd.Flags().GetString("file")
		keys, _ := cmd.Flags().GetStringArray("key")
		length, _ := cmd.Flags().GetInt64("length")

		var src io.Reader
		var plaintextLength int64
		if filePath == "-" {
			if length < 0 {
				return fmt.Errorf("--length is required when reading from stdin")
			}
			src = os.Stdin
			plaintextLength = length
		} else {
			f, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer f.Close()
			if length >= 0 {
				plaintextLength = length
			} else {
				info, err := f.Stat()
				if err != nil {
					return err
				}
				plaintextLength = info.Size()
			}
			src = f
		}

		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		go func() {
			defer pw.Close()
			defer mw.Close()
			for _, k := range keys {
				if err := mw.WriteField("encryption_keys", k); err != nil {
					pw.CloseWithError(err)
					return
				}
			}
			if err := mw.WriteField("plaintext_length", strconv.FormatInt(plaintextLength, 10)); err != nil {
				pw.CloseWithError(err)
				return
			}
			part, err := mw.CreateFormFile("data", path.Base(args[0]))
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if _, err := io.Copy(part, src); err != nil {
				pw.CloseWithError(err)
				return
			}
		}()

		resp, err := nbucketDo(nb, apiKey, master, "POST", "/put/"+args[0], map[string]string{
			"Content-Type": mw.FormDataContentType(),
		}, pr)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nbucketStatusError(resp)
		}
		body, _ := io.ReadAll(resp.Body)
		fmt.Println(strings.TrimSpace(string(body)))
		return nil
	},
}

var nbucketDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a named item",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		resp, err := nbucketDo(nb, apiKey, master, "DELETE", "/delete/"+args[0], nil, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			return nbucketStatusError(resp)
		}
		return nil
	},
}

var nbucketMetadataCmd = &cobra.Command{
	Use:   "metadata <name>",
	Short: "Show object metadata for a named item",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return nbucketJSONGet("/metadata/"+args[0], nil)
	},
}

var nbucketRevealCmd = &cobra.Command{
	Use:   "reveal <name>",
	Short: "Reveal the stored access token and managed key(s) for a named item",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return nbucketJSONGet("/reveal/"+args[0], nil)
	},
}

var nbucketKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage encryption key slots on a named item",
}

var nbucketKeysAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add an encryption key slot",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		newKey, _ := cmd.Flags().GetString("new-key")
		proofKey, _ := cmd.Flags().GetString("proof-key")

		body, err := json.Marshal(map[string]string{"new_encryption_key": newKey})
		if err != nil {
			return err
		}
		headers := map[string]string{"Content-Type": "application/json"}
		if proofKey != "" {
			headers["X-Encryption-Key"] = proofKey
		}
		resp, err := nbucketDo(nb, apiKey, master, "POST", "/keys/add/"+args[0], headers, bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			return nbucketStatusError(resp)
		}
		return nil
	},
}

var nbucketKeysRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an encryption key slot",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		removeKey, _ := cmd.Flags().GetString("remove-key")
		proofKey, _ := cmd.Flags().GetString("proof-key")
		unmanage, _ := cmd.Flags().GetBool("unmanage")

		body, err := json.Marshal(map[string]any{
			"remove_encryption_key": removeKey,
			"unmanage":              unmanage,
		})
		if err != nil {
			return err
		}
		headers := map[string]string{"Content-Type": "application/json"}
		if proofKey != "" {
			headers["X-Encryption-Key"] = proofKey
		}
		resp, err := nbucketDo(nb, apiKey, master, "POST", "/keys/remove/"+args[0], headers, bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			return nbucketStatusError(resp)
		}
		return nil
	},
}

func nbucketJSONGet(path string, extraHeaders map[string]string) error {
	nb, apiKey, master, err := requireNBucketAuth()
	if err != nil {
		return err
	}
	resp, err := nbucketDo(nb, apiKey, master, "GET", path, extraHeaders, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nbucketStatusError(resp)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		_, _ = os.Stdout.Write(raw)
		fmt.Println()
		return nil
	}
	_, _ = os.Stdout.Write(pretty.Bytes())
	fmt.Println()
	return nil
}
